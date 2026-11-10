#![recursion_limit = "512"]
//! Metadata-only Root review; never native Frame, full Reader, admission or release authority.
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};
type R<T> = Result<T, Box<dyn std::error::Error>>;
const IMAGE: &str =
    "/usr/local/lib/jetstreamer/horizon-duplicate722-authority-audit-tools-20261110-v1/check";
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

const GIB: u64 = 1 << 30;
const OLD_IID: &str = "722adc397ae24bb4b96d452783599f57";
const BASE: &str = "/home/sol/.jetstreamer-private/epoch173-independent-singleton-20261110-v1/";
const HELD: &str = "/var/lib/jetstreamer/held136-baseline-view-qualification-20261109-v1/";
fn changes() -> BTreeMap<String, i128> {
    let mut out = BTreeMap::new();
    for (path, amount) in [
        (
            "/home/sol/.jetstreamer-private/epoch172-independent-singleton-20261110-v1/ROOT_FRESH_STANDARD172_MANUAL_ADMISSION_AND_RESOURCE_BOOKING.json",
            69i128 << 30,
        ),
        (
            "/home/sol/.jetstreamer-private/epoch171-independent-singleton-20261110-v1/ROOT_FRESH_STANDARD171_MANUAL_ADMISSION_AND_RESOURCE_BOOKING.json",
            69i128 << 30,
        ),
        (
            "/home/sol/.jetstreamer-private/epoch170-independent-singleton-20261109-v1/ROOT_FRESH_STANDARD170_MANUAL_ADMISSION_AND_RESOURCE_BOOKING.json",
            68i128 << 30,
        ),
        (
            "/home/sol/.jetstreamer-private/epoch170-independent-singleton-20261109-v1/ROOT_METADATA256_CLOSED_DATA64_OS128_RETAINED.json",
            -(256i128 << 20),
        ),
        (
            "/home/sol/.jetstreamer-private/epoch170-independent-singleton-20261109-v1/ROOT_METADATA_PREPARATION_BOOKING.json",
            256i128 << 20,
        ),
        (
            "/var/lib/jetstreamer/old722-actor-future-qualification-20261109-v1/ROOT_NORMAL8_SUCCESSOR_GUARD_HANDOFF_BOOKING.json",
            1i128 << 30,
        ),
    ] {
        out.insert(path.into(), amount);
    }
    for (name, amount) in [
        (
            "ROOT_ONCE_ONLY_UNUSED_VERIFICATION32_FUTURE_ENDED_CURRENT_AUTHORITY.json",
            -(32i128 << 30),
        ),
        (
            "ROOT_ONCE_ONLY_UNUSED_VERIFICATION16_RETURNED_CURRENT_AUTHORITY.json",
            -(16i128 << 30),
        ),
        (
            "ROOT_ONCE_ONLY_OLD722_ACTOR48_MEMORY_ENDING_SELECTED.json",
            -(48i128 << 30),
        ),
        (
            "ROOT_VERIFICATION144_NATIVE16_PROFILE48_CURRENT_AUTHORITY.json",
            16i128 << 30,
        ),
        (
            "ROOT_ONCE_ONLY_HELD136_EFFECTIVE_MEMORY_SELECTED_CURRENT_AUTHORITY.json",
            -(68i128 << 30),
        ),
    ] {
        out.insert(format!("{HELD}{name}"), amount);
    }
    out
}
fn valid_changes(actual: &BTreeMap<String, i128>) -> R<()> {
    need(
        *actual == changes(),
        "unknown/rebooked/missing effective memory transition; new audit required",
    )
}
fn same_claim(first: &Value, second: &Value) -> R<()> {
    need(
        first["schema"] == "horizon-old722-actor-future-ended-v1"
            && second["schema"] == first["schema"]
            && first["ended_old722_actor_future"] == OLD_IID
            && second["ended_old722_actor_future"] == OLD_IID
            && first["ended_actor_memory_bytes"] == 48 * GIB
            && second["ended_actor_memory_bytes"] == 48 * GIB
            && first["ended_future_DATA_bytes"] == 480_969_228_288u64
            && second["ended_future_DATA_bytes"] == 0,
        "two exact same original actor endings required",
    )
}
fn corrected(memory: u64, data: u64) -> R<(u64, u64)> {
    need(
        memory == 708_249_923_584 && data == 6_101_056_700_210,
        "exact disputed head required",
    )?;
    Ok((
        memory.checked_add(48 * GIB).ok_or("memory overflow")?,
        data.checked_add(480_969_228_288).ok_or("DATA overflow")?,
    ))
}
fn chain(rows: &[Value]) -> R<(BTreeMap<String, Value>, Value)> {
    need(
        rows.len() == 45,
        "complete effective45-node ancestry required",
    )?;
    let mut docs = BTreeMap::new();
    let mut transitions = BTreeMap::new();
    let mut details = Vec::new();
    for row in rows {
        let name = s(&row["binding"], "path")?;
        need(!docs.contains_key(name), "duplicate ancestry node")?;
        docs.insert(name.into(), bound(&row["binding"])?);
    }
    for pair in rows.windows(2) {
        let a = s(&pair[0]["binding"], "path")?;
        let b = s(&pair[1]["binding"], "path")?;
        let key = s(&pair[0], "selected_parent_key")?;
        need(
            ["previous_complete_authority", "previous"].contains(&key),
            "unknown ancestry edge",
        )?;
        let before = &docs[b];
        let after = &docs[a];
        need(
            after[key] == pair[1]["binding"],
            "ancestry skips actual selected parent",
        )?;
        let delta = i128::from(n(after, "complete_projected_memory_bytes")?)
            - i128::from(n(before, "complete_projected_memory_bytes")?);
        if delta != 0 {
            transitions.insert(a.into(), delta);
            details.push(json!({"path":a,"parent":b,"memory_delta_bytes":delta.to_string()}));
        }
    }
    valid_changes(&transitions)?;
    need(
        s(&rows[0]["binding"], "path")? == format!("{BASE}ROOT_METADATA_PREPARATION_BOOKING.json")
            && s(&rows[44]["binding"], "path")?
                == "/var/lib/jetstreamer/old722-actor-future-qualification-20261109-v1/ROOT_NATIVE512_DRAINED_ONCE_ONLY_OLD722_ENDING_SELECTED.json",
        "exact current and first-selected ancestry endpoints required",
    )?;
    Ok((docs, json!(details)))
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
        plan["schema"] == "horizon-duplicate722-authority-audit-plan-v1"
            && plan["owner"] == "/root"
            && plan["primary_thread"] == "01a1af2a-9ce8-76a2-8939-b2112bd38f53",
        "exclusive Root plan required",
    )?;
    let mine = native("horizon-duplicate722-authority-audit-20261110-v1.service")?;
    need(
        mine["InvocationID"] == std::env::var("INVOCATION_ID")?
            && s(&mine, "MainPID")?.parse::<u32>()? == std::process::id()
            && mine["MemoryMax"] == "536870912"
            && mine["MemorySwapMax"] == "0"
            && mine["NRestarts"] == "0"
            && mine["Restart"] == "no",
        "exact funded own native scope required",
    )?;
    let rows = plan["chain"].as_array().ok_or("chain array")?;
    let (docs, trace) = chain(rows)?;
    let first = bound(&plan["first_actual_ending"])?;
    let second = bound(&plan["second_actual_actor_ending"])?;
    same_claim(&first, &second)?;
    let first_selected = &docs["/var/lib/jetstreamer/old722-actor-future-qualification-20261109-v1/ROOT_NATIVE512_DRAINED_ONCE_ONLY_OLD722_ENDING_SELECTED.json"];
    need(
        first_selected["complete_projected_memory_bytes"]
            == first["base_projected_memory_bytes_after"]
            && first_selected["complete_DATA_bytes"] == first["complete_DATA_bytes"],
        "first ending effective selection differs",
    )?;
    let admission = &docs["/home/sol/.jetstreamer-private/epoch170-independent-singleton-20261109-v1/ROOT_FRESH_STANDARD170_MANUAL_ADMISSION_AND_RESOURCE_BOOKING.json"];
    need(
        admission["complete_projected_memory_bytes"] == 718_987_341_824u64
            && admission["previous_complete_DATA_bytes"] == 6_301_980_639_026u64
            && n(&first, "complete_DATA_bytes")?.checked_add(64 << 20)
                == Some(n(admission, "previous_complete_DATA_bytes")?),
        "actual170 did not consume first effective DATA ending",
    )?;
    let actor = &docs[&format!("{HELD}ROOT_ONCE_ONLY_OLD722_ACTOR48_MEMORY_ENDING_SELECTED.json")];
    let data = &docs[&format!("{HELD}ROOT_ONCE_ONLY_OLD722_FUTURE_DATA_ENDING_SELECTED.json")];
    need(
        actor["original_producer_invocation_id"] == OLD_IID
            && actor["additional_once_only_ended_actor_memory_bytes"] == 48 * GIB
            && actor["genuine_memory_only_ending"] == plan["second_actual_actor_ending"]
            && actor["previous_complete_projected_memory_bytes"]
                == second["base_projected_memory_bytes_before"]
            && actor["complete_projected_memory_bytes"]
                == second["base_projected_memory_bytes_after"],
        "second actor selection differs",
    )?;
    need(
        data["original_producer_invocation_id"] == OLD_IID
            && data["additional_once_only_ended_unused_future_DATA_bytes"] == 480_969_228_288u64
            && n(data, "previous_complete_DATA_bytes")?.checked_sub(480_969_228_288)
                == Some(n(data, "complete_DATA_bytes")?),
        "second future DATA selection differs",
    )?;
    let mut data_rebook_candidates = Vec::new();
    for pair in rows.windows(2) {
        let name = s(&pair[0]["binding"], "path")?;
        let before = &docs[s(&pair[1]["binding"], "path")?];
        let after = &docs[name];
        if let (Some(x), Some(y)) = (
            after["complete_DATA_bytes"].as_u64(),
            before["complete_DATA_bytes"].as_u64(),
        ) {
            if x.checked_sub(y).is_some_and(|d| d >= 480_969_228_288) {
                data_rebook_candidates.push(name.to_owned());
            }
        }
    }
    need(
        data_rebook_candidates.is_empty(),
        "large intervening DATA rebooking requires a distinct audit",
    )?;
    let head = &docs[&format!("{BASE}ROOT_METADATA_PREPARATION_BOOKING.json")];
    let (memory, data_bytes) = corrected(
        n(head, "complete_projected_memory_bytes")?,
        n(head, "complete_DATA_bytes")?,
    )?;
    let fleet = bound(&plan["current_fleet"])?;
    need(
        fleet["live_replay_count"] == 7
            && fleet["proven_replay_count"] == 7
            && fleet["complete_DATA_authority"] == rows[0]["binding"],
        "current seven-owner fleet/head required",
    )?;
    let v = json!({"schema":"horizon-duplicate722-authority-audit-report-v1","owner":"/root","primary_thread":plan["primary_thread"],"recorded_unix_seconds":now()?,"plan":plan,"native_self":mine,"ancestry_nodes":45,"actual_memory_transition_trace":trace,"same_original_actor48_ending_selected_twice":true,"same_original_future_DATA_ending_selected_twice":true,"first_ending_consumed_by_actual170":true,"effective_memory_rebooking_in_complete_selected_chain":false,"large_DATA_rebooking_in_complete_selected_chain":false,"recommended_conservative_memory_add_back_bytes":48*GIB,"recommended_conservative_DATA_add_back_bytes":480_969_228_288u64,"proposed_corrected_complete_projected_memory_bytes":memory,"proposed_corrected_complete_DATA_bytes":data_bytes,"all_original_receipts_must_be_preserved":true,"shared64_bytes_still_retained":64*GIB,"native16_bytes_still_retained":16*GIB,"verification96_bytes_still_retained":96*GIB,"new_resource_credit_bytes":0,"producer_guard_timer_mutations":false,"remote_mutations":false,"replay_admission_authorized":false,"authority_selection_performed":false,"DATA_rebooking_check_scope":"effective selected ancestry numeric transitions; no claim of global artifact absence","next_gate":"Root may select only conservative add-back with immutable incident/correction evidence. Existing effective consumer/guard accounting must be reconciled separately before fresh admission; no new ending or capacity release."});
    durable(Path::new(s(&plan, "output")?), &v)?;
    println!(
        "{}",
        json!({"output":plan["output"],"ancestry_nodes":45,"proposed_corrected_memory_bytes":memory,"proposed_corrected_DATA_bytes":data_bytes,"new_resource_credit_bytes":0,"replay_admission_authorized":false})
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
    #[test]
    fn expected_transitions_are_exact_and_net_to_current() {
        let c = changes();
        assert_eq!(c.len(), 11);
        assert_eq!(
            644_899_155_968i128 + c.values().sum::<i128>(),
            708_249_923_584
        );
        assert!(valid_changes(&c).is_ok());
    }
    #[test]
    fn missing_transition_rejected() {
        let mut c = changes();
        c.pop_first();
        assert!(valid_changes(&c).is_err());
    }
    #[test]
    fn unknown_rebooking_rejected() {
        let mut c = changes();
        c.insert("extra48-rebook".into(), 48i128 << 30);
        assert!(valid_changes(&c).is_err());
    }
    #[test]
    fn mutated_ending_rejected() {
        let mut c = changes();
        let key = format!("{HELD}ROOT_ONCE_ONLY_OLD722_ACTOR48_MEMORY_ENDING_SELECTED.json");
        c.insert(key, -(47i128 << 30));
        assert!(valid_changes(&c).is_err());
    }
    #[test]
    fn exact_addback_preserves_original_head() {
        assert_eq!(
            corrected(708_249_923_584, 6_101_056_700_210).unwrap(),
            (759_789_531_136, 6_582_025_928_498)
        );
        assert!(corrected(759_789_531_136, 6_582_025_928_498).is_err());
    }
    #[test]
    fn crossed_head_rejected() {
        assert!(corrected(708_249_923_583, 6_101_056_700_210).is_err());
        assert!(corrected(708_249_923_584, 6_101_056_700_209).is_err());
    }
    fn ends() -> (Value, Value) {
        let a = json!({"schema":"horizon-old722-actor-future-ended-v1","ended_old722_actor_future":OLD_IID,"ended_actor_memory_bytes":48*GIB,"ended_future_DATA_bytes":480_969_228_288u64});
        let mut b = a.clone();
        b["ended_future_DATA_bytes"] = json!(0);
        (a, b)
    }
    #[test]
    fn exact_same_claim_accepted() {
        let (a, b) = ends();
        assert!(same_claim(&a, &b).is_ok());
    }
    #[test]
    fn distinct_claim_cannot_be_called_duplicate() {
        let (a, mut b) = ends();
        b["ended_old722_actor_future"] = json!("foreign");
        assert!(same_claim(&a, &b).is_err());
    }
    #[test]
    fn changed_caps_cannot_be_corrected() {
        let (mut a, b) = ends();
        a["ended_actor_memory_bytes"] = json!(47 * GIB);
        assert!(same_claim(&a, &b).is_err());
    }
    #[test]
    fn incomplete_chain_rejected() {
        assert!(chain(&[]).is_err());
    }
}
