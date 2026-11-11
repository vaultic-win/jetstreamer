#![recursion_limit = "512"]
//! Finite exact current seven-local2 epoch173 anonymous + disjoint global-kernel consumption report.
//! All promises and future pools retained; no host/uploader future envelope or release authority.
//! Raw prior endings stay historical; this checker selects no new release or consumer authority.
//! Existing hard promises stay intact; no RSS/file-cache credit or pool allocation authority.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
const IMAGE: &str = "/usr/local/lib/jetstreamer/horizon-local2-fulfilled-anon-host-kernel-memory-tools-20261110-v1/check";
mod data_guard_reader;
mod local2_owners;
const PRIMARY: &str = "01a1af2a-9ce8-76a2-8939-b2112bd38f53";
const GIB: u64 = 1 << 30;
const BASE_MEMORY: u64 = 759_789_531_136;
const LEGACY_BASE_MEMORY: u64 = 634_161_737_728;
const BASE_DATA: u64 = 6_582_025_928_498;
const LEGACY_BASE_DATA: u64 = 5_783_162_011_442;
const CAP: u64 = 68 * GIB;
const MARGIN: u64 = GIB;
const NOFOLLOW: i32 = 0x20000;
const CLOEXEC: i32 = 0x80000;
fn sha(raw: &[u8]) -> String {
    format!("{:x}", Sha256::digest(raw))
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn s<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str().with_context(|| format!("missing string {k}"))
}
fn n(v: &Value, k: &str) -> Result<u64> {
    v[k].as_u64()
        .with_context(|| format!("missing integer {k}"))
}
fn identity(m: &fs::Metadata) -> Value {
    json!([
        m.dev(),
        m.ino(),
        m.uid(),
        m.gid(),
        m.mode(),
        m.nlink(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec()
    ])
}
fn bytes(p: &Path, max: u64, virtual_file: bool) -> Result<Vec<u8>> {
    ensure!(
        p.is_absolute() && p.canonicalize()? == p,
        "canonical input path required"
    );
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(NOFOLLOW | CLOEXEC)
        .open(p)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file() && m.uid() == 0 && m.mode() & 0o022 == 0 && (virtual_file || m.len() <= max),
        "Root input custody/size differs"
    );
    let mut raw = Vec::new();
    Read::by_ref(&mut f).take(max + 1).read_to_end(&mut raw)?;
    ensure!(
        raw.len() as u64 <= max
            && (virtual_file || raw.len() as u64 == m.len())
            && identity(&m) == identity(&f.metadata()?)
            && identity(&m) == identity(&fs::symlink_metadata(p)?),
        "input identity or bound changed"
    );
    Ok(raw)
}
fn bound(b: &Value) -> Result<Value> {
    let raw = bytes(Path::new(s(b, "path")?), 32 << 20, false)?;
    ensure!(sha(&raw) == s(b, "sha256")?, "bound metadata hash differs");
    Ok(serde_json::from_slice(&raw)?)
}
fn native(name: &str) -> Result<Value> {
    ensure!(
        (name.ends_with(".service") || name.ends_with(".timer"))
            && !name.starts_with('-')
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.@".contains(&b)),
        "unsafe unit name"
    );
    let o=Command::new("/usr/bin/systemctl").env_remove("DBUS_SYSTEM_BUS_ADDRESS").env_remove("SYSTEMD_BUS_ADDRESS").env_remove("DBUS_SESSION_BUS_ADDRESS").env_remove("SYSTEMD_HOST").args(["show",name,"--no-pager","-pId,LoadState,ActiveState,SubState,InvocationID,MainPID,ControlPID,ControlGroup,NRestarts,Restart,Job,MemoryAccounting,MemoryMax,MemorySwapMax,Delegate,MemoryHigh,CPUQuotaPerSecUSec,TasksMax,ExecStart,ExecMainStartTimestamp,User,Group,WorkingDirectory,UMask,LimitNOFILE,Result,ExecMainStatus,Triggers,TriggeredBy,Type"]).output()?;
    ensure!(
        o.stderr.is_empty() && o.stdout.len() <= 65536,
        "native capture failed"
    );
    let mut m = serde_json::Map::new();
    for line in std::str::from_utf8(&o.stdout)?.lines() {
        let (k, v) = line.split_once('=').context("native delimiter")?;
        ensure!(
            m.insert(k.into(), json!(v)).is_none(),
            "duplicate native field"
        );
    }
    ensure!(
        o.status.success() || m.get("LoadState") == Some(&json!("not-found")),
        "native query failed"
    );
    ensure!(
        m.get("Id") == Some(&json!(name)),
        "native unit name differs"
    );
    Ok(Value::Object(m))
}
fn owner(actual: &Value, expected: &Value) -> Result<()> {
    ensure!(
        actual["LoadState"] == "loaded"
            && actual["ActiveState"] == "active"
            && actual["SubState"] == "running"
            && actual["ControlPID"] == "0"
            && actual["NRestarts"] == "0"
            && actual["Job"] == ""
            && s(actual, "MainPID")?.parse::<u64>()? > 0,
        "owner not stable running"
    );
    for k in ["Id", "InvocationID", "MainPID"] {
        ensure!(actual[k] == expected[k], "owner identity changed: {k}");
    }
    Ok(())
}
fn counter(text: &str, key: &str) -> Result<u64> {
    let mut keys = BTreeSet::new();
    let mut found = None;
    for line in text.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        ensure!(
            fields.len() == 2 && keys.insert(fields[0]),
            "invalid/duplicate cgroup counter"
        );
        let value = fields[1].parse::<u64>()?;
        if fields[0] == key {
            found = Some(value);
        }
    }
    found.context("required cgroup counter absent")
}
fn meminfo(raw: &str) -> Result<(u64, u64)> {
    let mut total = None;
    let mut available = None;
    for line in raw.lines() {
        let Some((key, value)) = line.split_once(':') else {
            anyhow::bail!("meminfo delimiter")
        };
        if ["MemTotal", "MemAvailable"].contains(&key) {
            let fields = value.split_whitespace().collect::<Vec<_>>();
            ensure!(
                fields.len() == 2 && fields[1] == "kB",
                "meminfo unit differs"
            );
            let value = fields[0]
                .parse::<u64>()?
                .checked_mul(1024)
                .context("meminfo overflow")?;
            let slot = if key == "MemTotal" {
                &mut total
            } else {
                &mut available
            };
            ensure!(slot.replace(value).is_none(), "duplicate meminfo field");
        }
    }
    let total = total.context("MemTotal absent")?;
    let available = available.context("MemAvailable absent")?;
    ensure!(
        total > 0 && available > 0 && available <= total,
        "invalid host available memory"
    );
    Ok((total, available))
}
fn host() -> Result<Value> {
    let raw = bytes(Path::new("/proc/meminfo"), 65536, true)?;
    let mut v = meminfo_kernel(std::str::from_utf8(&raw)?)?;
    v["raw_meminfo_sha256"] = json!(sha(&raw));
    Ok(v)
}

fn gauges(expected: &Value) -> Result<Value> {
    let name = s(expected, "Id")?;
    let unit = native(name)?;
    owner(&unit, expected)?;
    local2_owners::whole_service(&unit)?;
    ensure!(
        unit["MemoryAccounting"] == "yes"
            && unit["MemoryMax"] == "73014444032"
            && unit["MemorySwapMax"] == "0"
            && unit["Delegate"] == "no"
            && unit["ControlGroup"] == format!("/system.slice/{name}"),
        "exact68GiB zero-swap producer envelope required"
    );
    let path = Path::new("/sys/fs/cgroup").join(s(&unit, "ControlGroup")?.trim_start_matches('/'));
    ensure!(path.is_dir(), "original producer cgroup missing");
    let stat = bytes(&path.join("memory.stat"), 32768, true)?;
    let anon = counter(std::str::from_utf8(&stat)?, "anon")?;
    let current = std::str::from_utf8(&bytes(&path.join("memory.current"), 64, true)?)?
        .trim()
        .parse::<u64>()?;
    let swap = std::str::from_utf8(&bytes(&path.join("memory.swap.current"), 64, true)?)?
        .trim()
        .parse::<u64>()?;
    let events = bytes(&path.join("memory.events"), 16384, true)?;
    ensure!(
        counter(std::str::from_utf8(&events)?, "oom")? == 0
            && counter(std::str::from_utf8(&events)?, "oom_kill")? == 0,
        "producer has an OOM event"
    );
    ensure!(
        anon <= current && current <= CAP && swap == 0,
        "anonymous/current/cap/swap counters conflict"
    );
    Ok(
        json!({"unit":unit,"anonymous_bytes":anon,"memory_current_bytes":current,"memory_swap_current_bytes":swap,"memory_stat_sha256":sha(&stat),"memory_events_sha256":sha(&events),"anonymous_is_a_component_of_the_existing_hard_cap":true,"file_cache_RSS_and_other_cgroups_counted_bytes":0}),
    )
}
fn fulfilled(a: u64, b: u64, cap: u64) -> Result<u64> {
    ensure!(
        cap == CAP && a <= cap && b <= cap,
        "fulfilled amount exceeds original hard cap"
    );
    Ok(a.min(b).saturating_sub(MARGIN))
}
fn required(base: u64, candidate: u64, headroom: u64, already_resident: u64) -> Result<u64> {
    base.checked_add(candidate)
        .and_then(|v| v.checked_add(headroom))
        .and_then(|v| v.checked_sub(already_resident))
        .context("remaining-growth arithmetic overflow/underflow")
}
fn candidate_memory(plan: &Value) -> Result<u64> {
    ensure!(
        plan["candidate_epoch"] == 173
            && plan["candidate_actor_memory_bytes"] == 68 * GIB
            && plan["candidate_guard_memory_bytes"] == GIB
            && plan["additional_host_headroom_bytes"] == 16 * GIB,
        "exact173 actor68+guard1 and host16 required"
    );
    Ok(69 * GIB)
}
fn returned_projection(memory: u64, data: u64, returned: u64) -> Result<()> {
    ensure!(
        returned == 32 * GIB
            && memory.checked_sub(returned) == Some(LEGACY_BASE_MEMORY)
            && data == LEGACY_BASE_DATA,
        "unused32 return crossed or reapplied"
    );
    Ok(())
}
fn selected_legacy_endings(parent: &Value, fleet: &Value, plan: &Value) -> Result<()> {
    ensure!(
        parent["schema"]
            == "horizon-Root-once-only-unused-verification32-future-return-authority-v1"
            && parent["current_complete_fleet"] == plan["current_fleet"]
            && parent["additional_once_only_ended_unused_pool_memory_bytes"] == 32 * GIB
            && parent["effective_verification_pool_bytes"] == 96 * GIB
            && parent["all_six_retained_verifier_roles_bytes"] == 96 * GIB
            && parent["cancelled_unused_future_profile48_bytes"] == 48 * GIB
            && parent["all_existing_cgroup_caps_unchanged"] == true
            && parent["all_prior_once_only_endings_retained_without_reapplication"] == true
            && parent["physical_retirement_bytes"] == 0
            && parent["holding_credit_bytes"] == 0,
        "genuine legacy unused32 return selection required"
    );
    let before = bound(&parent["previous_complete_authority"])?;
    let check = bound(&parent["genuine_unused32_return_native_check"])?;
    let drain = bound(&parent["actual_native_drain"])?;
    let hands = bound(&parent["all_six_current_guard_handoffs"])?;
    ensure!(
        fleet["complete_DATA_authority"] == parent["previous_complete_authority"]
            && before["complete_projected_memory_bytes"]
                == fleet["complete_projected_memory_bytes"]
            && before["complete_DATA_bytes"] == LEGACY_BASE_DATA
            && hands["previous_complete_authority"] == before["previous_complete_authority"]
            && hands["all_six_original_producers_preserved"] == true
            && hands["temporary_extra_guard_bytes"] == 0
            && check["schema"] == "horizon-unused-verification32-return-native-check-v1"
            && check["current_fleet"] == plan["current_fleet"]
            && check["no_existing_cgroup_cap_lowered"] == true
            && check["additional_once_only_unused_pool_memory_ending_if_Root_selects_bytes"]
                == 32 * GIB
            && check["proposed_complete_projected_memory_bytes_after_return"] == LEGACY_BASE_MEMORY
            && check["verification_pool_after_return_bytes"] == 96 * GIB
            && check["retained_verification_caps_after_return_bytes"] == 96 * GIB
            && drain["MainPID"] == "0"
            && drain["ControlPID"] == "0"
            && drain["NRestarts"] == "0"
            && drain["ExecMainStatus"] == "0"
            && drain["Result"] == "success",
        "genuine complete native check, prior authority and unchanged current guard chain required"
    );
    returned_projection(
        n(fleet, "complete_projected_memory_bytes")?,
        n(fleet, "complete_DATA_bytes")?,
        32 * GIB,
    )
}
fn current_projection(parent: &Value, admission: &Value) -> Result<()> {
    ensure!(
        parent["schema"] == "horizon-existing-singleton173-metadata-preparation-v1"
            && parent["complete_projected_memory_bytes"] == DISPUTED_MEMORY
            && parent["complete_DATA_bytes"] == DISPUTED_DATA
            && parent["new_memory_promise_bytes"] == 0
            && parent["new_retained_DATA_bytes"] == 64u64 << 20
            && parent["previous_complete_DATA_bytes"] == 6_100_989_591_346u64
            && parent["normal_pool_bytes"] == 10 * GIB,
        "exact173 metadata-only preparation authority required"
    );
    ensure!(
        admission["schema"] == "horizon-fresh-standard172-resource-admission-v1"
            && admission["owner"] == "/root"
            && admission["primary_thread"] == PRIMARY
            && admission["complete_projected_memory_bytes"] == DISPUTED_MEMORY
            && admission["complete_DATA_bytes"] == 6_100_989_591_346u64
            && admission["previous_complete_DATA_bytes"] == LEGACY_BASE_DATA
            && admission["candidate_own_DATA_bytes"] == 309_237_645_312u64
            && admission["candidate_guard_metadata_DATA_bytes"] == 8 * GIB
            && admission["all_existing_hard_memory_promises_retained"] == true
            && admission["all_previous_once_only_endings_preserved_without_reapplication"] == true
            && admission["proven_replay_count"] == 6
            && admission["one_additional_guarded_lane_experiment"] == true
            && admission["normal_pool_bytes"] == 10 * GIB,
        "actual172 full admission and all prior promises required"
    );
    ensure!(
        LEGACY_BASE_MEMORY.checked_add(69 * GIB) == Some(DISPUTED_MEMORY)
            && LEGACY_BASE_DATA
                .checked_add(309_237_645_312)
                .and_then(|v| v.checked_add(8 * GIB))
                .and_then(|v| v.checked_add(64 << 20))
                == Some(DISPUTED_DATA),
        "current173 amounts crossed or a prior ending reapplied"
    );
    Ok(())
}
fn selected_prior_endings(parent: &Value, authority_binding: &Value) -> Result<()> {
    exact_binding(authority_binding, CORRECTION_PATH, CORRECTION_SHA)?;
    let old = bound(&parent["previous_complete_authority"])?;
    let audit = bound(&parent["genuine_native_duplicate_ending_audit"])?;
    let drain = bound(&parent["actual_native_audit_drain"])?;
    conservative_projection(parent, &old, &audit, &drain)?;
    selected_audit_chain(&audit, &parent["previous_complete_authority"])?;
    let admission = bound(&old["previous_complete_authority"])?;
    current_projection(&old, &admission)?;
    let legacy = bound(&admission["previous_complete_authority"])?;
    let legacy_fleet = bound(&legacy["current_complete_fleet"])?;
    ensure!(
        legacy["complete_projected_memory_bytes"] == LEGACY_BASE_MEMORY
            && legacy["complete_DATA_bytes"] == LEGACY_BASE_DATA
            && admission["current_complete_fleet"] == legacy["current_complete_fleet"],
        "actual172 historical pre-admission selected chain changed"
    );
    selected_legacy_endings(
        &legacy,
        &legacy_fleet,
        &json!({"current_fleet":legacy["current_complete_fleet"]}),
    )
}
// The old authority stays immutable historical input. This checker accepts only
// Root's exact conservative correction, and never selects or consumes an ending.
const DISPUTED_MEMORY: u64 = 708_249_923_584;
const DISPUTED_DATA: u64 = 6_101_056_700_210;
const ADD_BACK_MEMORY: u64 = 48 * GIB;
const ADD_BACK_DATA: u64 = 480_969_228_288;
const OLD_IID: &str = "722adc397ae24bb4b96d452783599f57";
const CORRECTION_PATH: &str = "/home/sol/.jetstreamer-private/epoch173-independent-singleton-20261110-v1/ROOT_CONSERVATIVE_DUPLICATE722_ADD_BACK_CURRENT_AUTHORITY.json";
const CORRECTION_SHA: &str = "ee31a884f0cbbb0f58f045eaaf9d9dd823fe8ec8852f560d0f5c21f79aa004d8";
const AUDIT_PATH: &str = "/home/sol/.jetstreamer-private/epoch173-independent-singleton-20261110-v1/duplicate722-authority-audit-qa-v2/ACTUAL_DUPLICATE722_AUTHORITY_AUDIT.json";
const AUDIT_SHA: &str = "b462365e124649771596844998dafb87c4f403466cf3fb5beb410d2f75fbf751";
const DRAIN_PATH: &str = "/home/sol/.jetstreamer-private/epoch173-independent-singleton-20261110-v1/duplicate722-authority-audit-qa-v2/ROOT_NATIVE_AUDIT_DRAINED_CONSERVATIVE_CORRECTION_NOT_YET_SELECTED.json";
const DRAIN_SHA: &str = "b2a4c4c70e749d6c620a45a14eabeed2867f97052b67779e6917fccef411236d";
fn exact_binding(b: &Value, path: &str, digest: &str) -> Result<()> {
    ensure!(
        *b == json!({"path":path,"sha256":digest}),
        "exact accepted metadata binding differs"
    );
    Ok(())
}
fn conservative_projection(
    corrected: &Value,
    old: &Value,
    audit: &Value,
    drain: &Value,
) -> Result<()> {
    ensure!(
        corrected["schema"]
            == "horizon-Root-conservative-duplicate722-addback-current-authority-v1"
            && corrected["owner"] == "/root"
            && corrected["primary_thread"] == PRIMARY
            && corrected["duplicate_original_invocation_id"] == OLD_IID
            && corrected["previous_complete_projected_memory_bytes"] == DISPUTED_MEMORY
            && corrected["previous_complete_DATA_bytes"] == DISPUTED_DATA
            && corrected["restored_conservative_actor48_bytes"] == ADD_BACK_MEMORY
            && corrected["restored_conservative_future_DATA_bytes"] == ADD_BACK_DATA
            && old["complete_projected_memory_bytes"] == DISPUTED_MEMORY
            && old["complete_DATA_bytes"] == DISPUTED_DATA
            && n(old, "complete_projected_memory_bytes")?.checked_add(ADD_BACK_MEMORY)
                == Some(BASE_MEMORY)
            && n(old, "complete_DATA_bytes")?.checked_add(ADD_BACK_DATA) == Some(BASE_DATA)
            && corrected["complete_projected_memory_bytes"] == BASE_MEMORY
            && corrected["complete_DATA_bytes"] == BASE_DATA
            && corrected["normal_pool_bytes"] == 10 * GIB
            && corrected["existing_native16_pool_bytes"] == 16 * GIB
            && corrected["new_memory_promise_bytes"] == 0
            && corrected["current_extra_QA_memory_bytes"] == 0
            && corrected["selected_new_release_bytes"] == 0
            && corrected["new_memory_or_DATA_credit_bytes"] == 0
            && corrected["physical_or_holding_credit_bytes"] == 0
            && corrected["old_head_disputed_and_superseded_for_current_accounting"] == true
            && corrected["first_original_ending_retained_once"] == true
            && corrected["second_original_actor_and_DATA_deduction_counteracted_conservatively"]
                == true
            && corrected["all_original_receipts_and_raw_histories_retained"] == true
            && corrected["existing_all_seven_hard_caps_unchanged"] == true
            && corrected["existing_all_seven_producers_preserved"] == true
            && corrected["all_verifier96_native16_shared64_pools_retained"] == true
            && corrected["native_Frame_or_full_Reader_acceptance_claimed"] == false
            && corrected["replay_admission_authorized"] == false
            && corrected["producer_or_guard_mutations"] == false
            && corrected["remote_mutations"] == false,
        "conservative exact once-only add-back changed or reapplied"
    );
    exact_binding(
        &corrected["genuine_native_duplicate_ending_audit"],
        AUDIT_PATH,
        AUDIT_SHA,
    )?;
    exact_binding(
        &corrected["actual_native_audit_drain"],
        DRAIN_PATH,
        DRAIN_SHA,
    )?;
    ensure!(
        audit["schema"] == "horizon-duplicate722-authority-audit-report-v1"
            && audit["owner"] == "/root"
            && audit["primary_thread"] == PRIMARY
            && audit["ancestry_nodes"] == 45
            && audit["same_original_actor48_ending_selected_twice"] == true
            && audit["same_original_future_DATA_ending_selected_twice"] == true
            && audit["first_ending_consumed_by_actual170"] == true
            && audit["effective_memory_rebooking_in_complete_selected_chain"] == false
            && audit["large_DATA_rebooking_in_complete_selected_chain"] == false
            && audit["recommended_conservative_memory_add_back_bytes"] == ADD_BACK_MEMORY
            && audit["recommended_conservative_DATA_add_back_bytes"] == ADD_BACK_DATA
            && audit["proposed_corrected_complete_projected_memory_bytes"] == BASE_MEMORY
            && audit["proposed_corrected_complete_DATA_bytes"] == BASE_DATA
            && audit["verification96_bytes_still_retained"] == 96 * GIB
            && audit["native16_bytes_still_retained"] == 16 * GIB
            && audit["shared64_bytes_still_retained"] == 64 * GIB
            && audit["all_original_receipts_must_be_preserved"] == true
            && audit["new_resource_credit_bytes"] == 0
            && audit["producer_guard_timer_mutations"] == false
            && audit["remote_mutations"] == false
            && audit["replay_admission_authorized"] == false
            && audit["authority_selection_performed"] == false
            && drain["actual_audit"] == corrected["genuine_native_duplicate_ending_audit"]
            && drain["native_pool_bytes"] == 16 * GIB
            && drain["new_credit_bytes"] == 0
            && drain["selection_performed"] == false
            && drain["healthy_producers_untouched"] == true,
        "genuine native duplicate audit or drained scope differs"
    );
    let live = &audit["native_self"];
    ensure!(
        live["Id"] == "horizon-duplicate722-authority-audit-20261110-v2.service"
            && live["InvocationID"] == "f74a1c6af7234c19b0cf3e99209db160"
            && live["LoadState"] == "loaded"
            && live["ActiveState"] == "active"
            && live["SubState"] == "running"
            && live["ControlPID"] == "0"
            && s(live, "MainPID")?.parse::<u64>()? > 1
            && live["Job"] == ""
            && live["MemoryMax"] == "536870912"
            && live["MemorySwapMax"] == "0"
            && live["NRestarts"] == "0"
            && live["Restart"] == "no",
        "accepted genuine native audit original identity differs"
    );
    for key in ["MainPID", "ControlPID", "NRestarts", "ExecMainStatus"] {
        ensure!(
            drain["native"][key] == "0",
            "original audit not drained: {key}"
        );
    }
    ensure!(
        drain["native"]["Result"] == "success"
            && drain["native"]["ActiveState"] == "inactive"
            && drain["native"]["SubState"] == "dead",
        "original audit did not finish successfully"
    );
    Ok(())
}
fn selected_audit_chain(audit: &Value, old_binding: &Value) -> Result<()> {
    let rows = audit["plan"]["chain"]
        .as_array()
        .context("actual selected audit chain")?;
    ensure!(
        rows.len() == 45 && rows[0]["binding"] == *old_binding,
        "complete45-node old selected ancestry required"
    );
    let mut paths = BTreeSet::new();
    let mut docs = Vec::new();
    for row in rows {
        ensure!(
            paths.insert(s(&row["binding"], "path")?),
            "repeated selected authority node"
        );
        docs.push(bound(&row["binding"])?);
    }
    let mut trace = Vec::new();
    for (index, pair) in rows.windows(2).enumerate() {
        let key = s(&pair[0], "selected_parent_key")?;
        ensure!(
            ["previous_complete_authority", "previous"].contains(&key)
                && docs[index][key] == pair[1]["binding"],
            "selected ancestry edge changed"
        );
        let delta = i128::from(n(&docs[index], "complete_projected_memory_bytes")?)
            - i128::from(n(&docs[index + 1], "complete_projected_memory_bytes")?);
        if delta != 0 {
            trace.push(json!({"path":pair[0]["binding"]["path"],"parent":pair[1]["binding"]["path"],"memory_delta_bytes":delta.to_string()}));
        }
    }
    ensure!(
        json!(trace) == audit["actual_memory_transition_trace"],
        "genuine audit transition trace changed"
    );
    let first = bound(&audit["plan"]["first_actual_ending"])?;
    let second = bound(&audit["plan"]["second_actual_actor_ending"])?;
    ensure!(
        first["schema"] == "horizon-old722-actor-future-ended-v1"
            && second["schema"] == first["schema"]
            && first["ended_old722_actor_future"] == OLD_IID
            && second["ended_old722_actor_future"] == OLD_IID
            && first["ended_actor_memory_bytes"] == ADD_BACK_MEMORY
            && second["ended_actor_memory_bytes"] == ADD_BACK_MEMORY
            && first["ended_future_DATA_bytes"] == ADD_BACK_DATA
            && second["ended_future_DATA_bytes"] == 0
            && docs[44]["complete_projected_memory_bytes"]
                == first["base_projected_memory_bytes_after"]
            && docs[44]["complete_DATA_bytes"] == first["complete_DATA_bytes"],
        "raw original endings or first effective selection changed"
    );
    Ok(())
}
fn utc_seconds(raw: &str) -> Result<u64> {
    let b = raw.as_bytes();
    ensure!(
        b.len() == 20
            && b[4] == b'-'
            && b[7] == b'-'
            && b[10] == b'T'
            && b[13] == b':'
            && b[16] == b':'
            && b[19] == b'Z'
            && b.iter()
                .enumerate()
                .all(|(i, c)| [4, 7, 10, 13, 16, 19].contains(&i) || c.is_ascii_digit()),
        "strict UTC sample clock required"
    );
    let y = raw[0..4].parse::<u64>()?;
    let m = raw[5..7].parse::<usize>()?;
    let d = raw[8..10].parse::<u64>()?;
    let h = raw[11..13].parse::<u64>()?;
    let min = raw[14..16].parse::<u64>()?;
    let sec = raw[17..19].parse::<u64>()?;
    ensure!(
        (1970..=9999).contains(&y) && (1..=12).contains(&m) && h < 24 && min < 60 && sec < 60,
        "sample clock components out of range"
    );
    let leap = |year: u64| {
        year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
    };
    let months = [
        31,
        if leap(y) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    ensure!(
        d > 0 && d <= months[m - 1],
        "sample calendar date out of range"
    );
    let days = (1970..y)
        .map(|year| if leap(year) { 366u64 } else { 365 })
        .sum::<u64>()
        + months[..m - 1].iter().sum::<u64>()
        + d
        - 1;
    Ok(days * 86400 + h * 3600 + min * 60 + sec)
}
fn fleet_context(fleet: &Value, observer: &Value, plan: &Value, clock: u64) -> Result<u64> {
    let sampled = utc_seconds(s(observer, "recorded_at_utc")?)?;
    ensure!(
        fleet["schema"] == "horizon-Root-complete-fleet-operational-review-v1"
            && fleet["owner"] == "/root"
            && fleet["primary_thread"] == PRIMARY
            && fleet["live_replay_count"] == 7
            && fleet["active_producer_count"] == 7
            && fleet["proven_replay_count"] == 7
            && fleet["guarded_bootstrap_owner_count"] == 0
            && fleet["complete_projected_memory_bytes"] == BASE_MEMORY
            && fleet["complete_DATA_bytes"] == CURRENT_DATA
            && fleet["normal_pool_bytes"] == 10 * GIB
            && fleet["complete_DATA_authority"] == plan["current_complete_authority"]
            && observer["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && fleet["sampled_at_utc"] == observer["recorded_at_utc"]
            && utc_seconds(s(observer, "completed_at_utc")?)? >= sampled
            && utc_seconds(s(observer, "completed_at_utc")?)? <= clock
            && clock.checked_sub(sampled).is_some_and(|age| age <= 1800),
        "fresh exact-observer seven-owner corrected context required"
    );
    Ok(sampled)
}

const TRUE_HOST_COMPONENT: u64 = 43_603_734_528;
const OUTSIDE_INPUT_COMPONENT: u64 = 2_684_354_560;
const CURRENT_DATA: u64 = 6_229_838_610_226;
const HEAD_PATH: &str = "/usr/local/lib/jetstreamer/horizon-original154-future-data-current-authority-20261110-v1/authority.json";
const HEAD_SHA: &str = "2f88b7f91cc6df70804cd96027efbd0e18cb6452a48e76d813673b556d727caa";
const SEMANTICS_PATH: &str =
    "/usr/local/lib/jetstreamer/horizon-host-kernel-counter-semantics-20261110-v1/semantics.json";
const SEMANTICS_SHA: &str = "b3ffced936265a20449f436037cc34146b6e8dc3c724341710cce277abaa2cdf";
const KERNEL_FIELDS: [&str; 3] = ["SUnreclaim", "KernelStack", "PageTables"];
fn sum_checked(values: impl IntoIterator<Item = u64>) -> Result<u64> {
    values.into_iter().try_fold(0u64, |a, b| {
        a.checked_add(b).context("component sum overflow")
    })
}
fn current_head_projection(head: &Value) -> Result<()> {
    ensure!(
        head["schema"]
            == "horizon-Root-once-only-original154-unused-future-DATA-selection-authority-v1"
            && head["owner"] == "/root"
            && head["primary_thread"] == PRIMARY
            && head["complete_projected_memory_bytes"] == BASE_MEMORY
            && head["previous_complete_DATA_bytes"] == BASE_DATA
            && head["complete_DATA_bytes"] == CURRENT_DATA
            && head["additional_once_only_ended_unused_future_DATA_bytes"] == 352_187_318_272u64
            && head["normal_pool_bytes"] == 10 * GIB
            && head["retained_native16_pool_bytes"] == 16 * GIB
            && head["effective_verification_pool_bytes"] == 96 * GIB
            && head["retained_shared_pool_bytes"] == 64 * GIB
            && head["old154_memory64_ending_reapplied_bytes"] == 0
            && head["new_memory_credit_bytes"] == 0
            && head["all_previous_once_only_endings_retained_without_reapplication"] == true
            && head["all_seven_original_producers_and_caps_preserved"] == true
            && head["native_Frame_or_full_Reader_acceptance_claimed"] == false
            && head["replay_admission_authorized"] == false
            && head["producer_guard_timer_mutations"] == false
            && head["remote_mutations"] == false,
        "exact memory-preserving current DATA-only head required"
    );
    Ok(())
}
fn accepted_current_head(plan: &Value) -> Result<(Value, Value)> {
    exact_binding(&plan["current_complete_authority"], HEAD_PATH, HEAD_SHA)?;
    let head = bound(&plan["current_complete_authority"])?;
    current_head_projection(&head)?;
    exact_binding(
        &head["previous_complete_authority"],
        CORRECTION_PATH,
        CORRECTION_SHA,
    )?;
    let correction = bound(&head["previous_complete_authority"])?;
    for key in [
        "genuine_native_check",
        "genuine_once_only_ending",
        "actual_native_ending_drain",
    ] {
        let _ = bound(&head[key])?;
    }
    Ok((head, correction))
}
fn historical_host_component() -> Result<Value> {
    let ob = json!({"path":"/var/lib/jetstreamer-horizon-observe-eleven-focus-20261017-v1/sample-20261109T153022Z-postcompletion154-v1.json","sha256":"e6a0713f158869752e84560f11f52d52a7f9dfb405038e5ee2d4af031e6b2334"});
    let rb = json!({"path":"/var/lib/jetstreamer/horizon-failed4-current-accounting-reader-20261104-v1/e6a0713f158869752e84560f11f52d52a7f9dfb405038e5ee2d4af031e6b2334-cold185-722adc397ae24bb4b96d452783599f57/raw-accounting.json","sha256":"d783309cf31a26a572b0ad9113c154e4c86604fe1c8a8f882b17f3a6285f7274"});
    let sb = json!({"path":"/var/lib/jetstreamer/horizon-original199-parent-memory-selection-v1/e6a0713f158869752e84560f11f52d52a7f9dfb405038e5ee2d4af031e6b2334/select-1/selection.json","sha256":"04a6c68f71a4a3a763a2a529b72b3eaa14b82728bfa46919073eb12098074b92"});
    let o = bound(&ob)?;
    let raw = bound(&rb)?;
    let selection = bound(&sb)?;
    ensure!(
        o["schema"] == "jetstreamer-horizon-live-resource-sample-v2"
            && o["recorded_at_utc"] == "2026-11-09T15:30:22Z"
            && o["replays"].as_array().is_some_and(Vec::is_empty),
        "original measured-host observer scope"
    );
    let mut measured = 0u64;
    for end in ["before", "after"] {
        let h = &o["host_resident_memory"][end];
        ensure!(
            h["status"] == "observed"
                && h["rss"]["census_stable"] == true
                && h["rss"]["error"].is_null(),
            "original complete host census"
        );
        let kernel = sum_checked(
            ["Slab", "KernelStack", "PageTables", "Percpu"]
                .into_iter()
                .map(|k| n(&h["kernel_components_bytes"], k))
                .collect::<Result<Vec<_>>>()?,
        )?;
        measured = measured.max(sum_checked([n(&h["rss"], "aggregate_rss_bytes")?, kernel])?);
    }
    let peers = raw["active_peer_allocations"]
        .as_array()
        .context("raw original peers")?;
    let mut direct = 0;
    let mut typed = 0;
    for p in peers {
        let pool = match p.get("native_pool_suballocation") {
            Some(Value::Bool(v)) => Some(*v),
            None => None,
            Some(_) => anyhow::bail!("malformed original pool tag"),
        };
        if pool != Some(true) {
            direct = sum_checked([direct, n(p, "memory_max_bytes")?])?;
        }
        if pool == Some(false) {
            typed = sum_checked([typed, n(p, "memory_max_bytes")?])?;
        }
    }
    let selected = &selection["selection"];
    ensure!(
        measured == TRUE_HOST_COMPONENT
            && direct.checked_sub(typed) == Some(OUTSIDE_INPUT_COMPONENT)
            && direct == 834_834_268_160
            && typed == 832_149_913_600
            && selected["raw_total_memory_promises_bytes"] == 1_102_313_172_992u64
            && selected["raw_peer_memory_bytes"] == typed
            && sum_checked([measured, (128 + 16 + 64) * GIB + GIB / 2, direct])?
                == 1_102_313_172_992u64,
        "true measured-host component cannot absorb missing-tag input promises"
    );
    Ok(
        json!({"observer":ob,"raw_accounting":rb,"selected_memory":sb,
        "true_measured_host_component_bytes":measured,"outside_input_component_excluded_bytes":OUTSIDE_INPUT_COMPONENT,
        "original_raw_rows_and_all_promises_retained":true,"resource_credit_bytes":0}),
    )
}
fn semantics_contract() -> Result<Value> {
    let b = json!({"path":SEMANTICS_PATH,"sha256":SEMANTICS_SHA});
    let v = bound(&b)?;
    let root = Path::new(SEMANTICS_PATH)
        .parent()
        .context("semantics deployment parent")?;
    let seal_raw = bytes(&root.join("deployment-seal-receipt.json"), 1 << 20, false)?;
    let seal: Value = serde_json::from_slice(&seal_raw)?;
    let refs = v["reference_sources"]
        .as_array()
        .context("kernel source references")?;
    let members = seal["members"]
        .as_array()
        .context("normal semantic source members")?;
    ensure!(
        v["schema"] == "horizon-linux68-anon-disjoint-kernel-counter-semantics-v1"
            && v["global_kernel_fields"] == json!(KERNEL_FIELDS)
            && v["supported_architecture"] == "x86_64"
            && v["supported_releases"] == json!(["6.8.0-146-generic", "6.8.0-149-generic"])
            && v["historical_true_host_component_bytes"] == TRUE_HOST_COMPONENT
            && v["missing_pool_tag_input_promises_bytes_excluded"] == OUTSIDE_INPUT_COMPONENT
            && v["global_kernel_ledger_entries"] == 1
            && v["global_additional_margin_bytes"] == GIB
            && v["host_future_envelope_proven"] == false
            && v["uploader_future_envelope_proven"] == false
            && v["resource_credit_bytes"] == 0
            && v["replay_admission_authorized"] == false
            && seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["destination"] == json!(root)
            && members.len() == refs.len() + 1,
        "exact normally sealed Linux68 counter semantics required"
    );
    for (name, digest) in
        std::iter::once(("semantics.json", SEMANTICS_SHA)).chain(refs.iter().map(|r| {
            (
                r["name"].as_str().unwrap_or(""),
                r["sha256"].as_str().unwrap_or(""),
            )
        }))
    {
        ensure!(
            !name.is_empty()
                && !name.contains('/')
                && digest.len() == 64
                && members
                    .iter()
                    .filter(|m| m["name"] == name && m["sha256"] == digest)
                    .count()
                    == 1
                && sha(&bytes(&root.join(name), 2 << 20, false)?) == digest,
            "normal kernel semantic source member differs"
        );
    }
    Ok(
        json!({"binding":b,"normal_seal_sha256":sha(&seal_raw),"source_members_rehashed":refs.len(),
        "kernel_release_match_at_native_endpoints_required":true,"future_memory_bound_or_release_authority":false}),
    )
}
fn kernel_identity() -> Result<Value> {
    let release = bytes(Path::new("/proc/sys/kernel/osrelease"), 256, true)?;
    let release = std::str::from_utf8(&release)?.trim();
    let boot = bytes(Path::new("/proc/sys/kernel/random/boot_id"), 256, true)?;
    let boot = std::str::from_utf8(&boot)?.trim();
    let machine = Command::new("/usr/bin/uname")
        .env_clear()
        .env("LC_ALL", "C")
        .arg("-m")
        .output()?;
    ensure!(
        machine.status.success() && machine.stderr.is_empty() && machine.stdout.len() <= 64,
        "native architecture query failed"
    );
    let machine = std::str::from_utf8(&machine.stdout)?.trim();
    kernel_identity_shape(release, boot, machine)?;
    Ok(json!({"release":release,"boot_id":boot,"machine":machine}))
}
fn kernel_identity_shape(release: &str, boot: &str, machine: &str) -> Result<()> {
    ensure!(
        ["6.8.0-146-generic", "6.8.0-149-generic"].contains(&release)
            && machine == "x86_64"
            && boot.len() == 36
            && boot.bytes().enumerate().all(|(i, c)| {
                if [8, 13, 18, 23].contains(&i) {
                    c == b'-'
                } else {
                    c.is_ascii_digit() || (b'a'..=b'f').contains(&c)
                }
            }),
        "unsupported kernel ABI release or boot identity"
    );
    Ok(())
}
fn same_kernel(a: &Value, b: &Value) -> Result<()> {
    for side in [a, b] {
        kernel_identity_shape(
            s(side, "release")?,
            s(side, "boot_id")?,
            s(side, "machine")?,
        )?;
    }
    ensure!(
        a == b,
        "kernel boot, release or architecture changed during the finite sample"
    );
    Ok(())
}
fn meminfo_kernel(raw: &str) -> Result<Value> {
    let (total, available) = meminfo(raw)?;
    let required = [
        "Slab",
        "SReclaimable",
        "SUnreclaim",
        "KernelStack",
        "PageTables",
        "Percpu",
    ];
    let mut fields = std::collections::BTreeMap::new();
    for line in raw.lines() {
        let (key, value) = line.split_once(':').context("meminfo kernel delimiter")?;
        if required.contains(&key) {
            let words = value.split_whitespace().collect::<Vec<_>>();
            ensure!(
                words.len() == 2 && words[1] == "kB",
                "exact kernel counter units"
            );
            let amount = words[0]
                .parse::<u64>()?
                .checked_mul(1024)
                .context("kernel counter byte overflow")?;
            ensure!(
                amount <= total && fields.insert(key, amount).is_none(),
                "kernel counter duplicate or exceeds physical memory"
            );
        }
    }
    ensure!(
        fields.len() == required.len(),
        "required kernel counter missing"
    );
    // Linux6.8 meminfo prints Slab and both children from the same two locals.
    // A mismatch is not a harmless concurrent-read exception for this ABI.
    ensure!(
        fields["SReclaimable"].checked_add(fields["SUnreclaim"]) == Some(fields["Slab"]),
        "Slab decomposition violates source-bound same-local ABI"
    );
    let components: serde_json::Map<String, Value> = KERNEL_FIELDS
        .into_iter()
        .map(|k| (k.into(), json!(fields[k])))
        .collect();
    ensure!(
        sum_checked(components.values().map(|v| v.as_u64().unwrap_or(u64::MAX)))? <= total,
        "disjoint kernel subtotal exceeds host"
    );
    Ok(
        json!({"total_bytes":total,"available_bytes":available,"kernel_components_bytes":components,
        "excluded_reclaimable_slab_bytes":fields["SReclaimable"],"whole_slab_not_credited_bytes":fields["Slab"],"diagnostic_only_Percpu_bytes":fields["Percpu"],
        "kernel_ledger_scope":"one global census; no cgroup kernel children or overlapping Vmalloc counters"}),
    )
}
fn kernel_fulfilled(a: &Value, b: &Value, budget: u64) -> Result<Value> {
    ensure!(
        budget == TRUE_HOST_COMPONENT,
        "only the true historical measured-host component may be fulfilled"
    );
    let mut minima = serde_json::Map::new();
    for side in [a, b] {
        let map = side["kernel_components_bytes"]
            .as_object()
            .context("global kernel component map")?;
        ensure!(
            map.len() == KERNEL_FIELDS.len() && KERNEL_FIELDS.iter().all(|k| map.contains_key(*k)),
            "global kernel ledger cannot mix whole Slab, reclaimable or child counters"
        );
    }
    for key in KERNEL_FIELDS {
        minima.insert(
            key.into(),
            json!(
                n(&a["kernel_components_bytes"], key)?.min(n(&b["kernel_components_bytes"], key)?)
            ),
        );
    }
    let total = sum_checked(minima.values().map(|v| v.as_u64().unwrap_or(u64::MAX)))?;
    let consumed = total.saturating_sub(GIB).min(budget);
    Ok(
        json!({"global_component_minima_bytes":minima,"pre_margin_unique_kernel_bytes":total,
        "additional_global_margin_bytes":GIB,"already_consumed_kernel_bytes":consumed,
        "charged_once_to_true_historical_host_component_bytes":budget,"unfulfilled_host_component_bytes":budget-consumed,
        "outside_input_component_counted_bytes":0,"shared_native_verifier_or_actor_kernel_credit_bytes":0,
        "resource_credit_bytes":0,"hard_promises_released_bytes":0}),
    )
}

fn own_unit(plan: &Value) -> Result<&'static str> {
    match s(plan, "purpose")? {
        "qualification" => {
            Ok("horizon-local2-fulfilled-anon-host-kernel-memory-qualification-20261110-v1.service")
        }
        "epoch173-admission-check" => Ok(
            "horizon-local2-fulfilled-anon-host-kernel-memory-epoch173-admission-check-20261110-v1.service",
        ),
        _ => anyhow::bail!("unqualified purpose"),
    }
}
fn run(plan: &Value) -> Result<Value> {
    ensure!(
        plan["schema"] == "horizon-current-local2-fulfilled-anon-memory-check-plan-v1"
            && plan["owner"] == "/root"
            && plan["primary_thread"] == PRIMARY,
        "exclusive Root plan required"
    );
    let (parent, correction) = accepted_current_head(plan)?;
    let fleet = bound(&plan["current_fleet"])?;
    let observer = bound(&fleet["observer"])?;
    let sampled = fleet_context(&fleet, &observer, plan, now()?)?;
    let current_owners = local2_owners::validate_fleet(&fleet)?;
    local2_owners::validate_request(plan)?;
    selected_prior_endings(&correction, &parent["previous_complete_authority"])?;
    let host_component = historical_host_component()?;
    let counter_semantics = semantics_contract()?;
    let candidate = candidate_memory(plan)?;
    let own = own_unit(plan)?;
    let mine = native(own)?;
    ensure!(
        mine["InvocationID"] == std::env::var("INVOCATION_ID")?
            && s(&mine, "MainPID")?.parse::<u32>()? == std::process::id()
            && mine["MemoryMax"] == "536870912"
            && mine["MemorySwapMax"] == "0"
            && mine["NRestarts"] == "0"
            && mine["Restart"] == "no"
            && fs::read_to_string("/proc/self/cgroup")?.trim() == format!("0::/system.slice/{own}"),
        "own funded512MiB identity differs"
    );
    let rows = fleet["actual_executing_replays"]
        .as_array()
        .context("complete seven replays")?;
    ensure!(rows.len() == 7, "seven rows required");
    let mut epochs = BTreeSet::new();
    let mut iids = BTreeSet::new();
    for row in rows {
        ensure!(
            epochs.insert(n(row, "epoch")?) && iids.insert(s(&row["unit"], "InvocationID")?),
            "duplicate replay epoch/IID"
        );
    }
    ensure!(
        epochs == BTreeSet::from([166, 167, 168, 169, 170, 171, 172]),
        "exact live epoch set required"
    );
    let stable = fleet["stable_non_replay_owners"]
        .as_object()
        .context("stable background census")?;
    ensure!(
        stable.len() == 2,
        "two persistent background owners required"
    );
    let mut background_before = serde_json::Map::new();
    for (name, expected) in stable {
        let actual = native(name)?;
        owner(&actual, expected)?;
        background_before.insert(name.clone(), actual);
    }
    let started = now()?;
    let guard_before = local2_owners::current_guards(plan, &fleet, now()?)?;
    let kernel_before = kernel_identity()?;
    let host_before = host()?;
    let mut before = Vec::new();
    for row in rows {
        before.push(gauges(&row["unit"])?);
    }
    let mut after = Vec::new();
    for row in rows {
        after.push(gauges(&row["unit"])?);
    }
    let host_after = host()?;
    let kernel_after = kernel_identity()?;
    let mut total = 0u64;
    let mut credits = Vec::new();
    for (a, b) in before.iter().zip(&after) {
        ensure!(
            a["unit"] == b["unit"],
            "producer native identity/envelope changed during sample"
        );
        let amount = fulfilled(n(a, "anonymous_bytes")?, n(b, "anonymous_bytes")?, CAP)?;
        total = total
            .checked_add(amount)
            .context("fulfilled sum overflow")?;
        credits.push(json!({"unit":a["unit"]["Id"],"invocation_id":a["unit"]["InvocationID"],"conservative_nonreclaimable_fulfilled_bytes":amount,"per_lane_additional_margin_bytes":MARGIN}));
    }
    let mut background_after = serde_json::Map::new();
    for (name, expected) in stable {
        let actual = native(name)?;
        owner(&actual, expected)?;
        background_after.insert(name.clone(), actual);
    }
    let guard_after = local2_owners::current_guards(plan, &fleet, now()?)?;
    same_kernel(&kernel_before, &kernel_after)?;
    ensure!(
        background_before == background_after
            && bound(&plan["current_complete_authority"])? == parent
            && host_before["total_bytes"] == host_after["total_bytes"]
            && now()?
                .checked_sub(started)
                .is_some_and(|elapsed| elapsed <= 30),
        "background/authority/host changed or finite sample expired"
    );
    fleet_context(
        &bound(&plan["current_fleet"])?,
        &bound(&fleet["observer"])?,
        plan,
        now()?,
    )?;
    let available = n(&host_before, "available_bytes")?.min(n(&host_after, "available_bytes")?);
    let full = required(BASE_MEMORY, candidate, 16 * GIB, 0)?;
    let kernel_consumption = kernel_fulfilled(&host_before, &host_after, TRUE_HOST_COMPONENT)?;
    let kernel_amount = n(&kernel_consumption, "already_consumed_kernel_bytes")?;
    let disjoint_consumed = sum_checked([total, kernel_amount])?;
    let without_kernel = required(BASE_MEMORY, candidate, 16 * GIB, total)?;
    let remaining = required(BASE_MEMORY, candidate, 16 * GIB, disjoint_consumed)?;
    Ok(
        json!({"schema":"horizon-current-local2-fulfilled-anon-host-kernel-memory-native-check-v1","owner":"/root","primary_thread":PRIMARY,"recorded_unix_seconds":now()?,"planning_sample_expires_unix_seconds":now()?.checked_add(300).context("expiry overflow")?.min(sampled.checked_add(1800).context("sample expiry overflow")?).min(local2_owners::protection_expiry(&guard_after)?),"plan":plan,"native_self":mine,"current_local2_owner_bindings":current_owners,"protective_guards_before":guard_before,"protective_guards_after":guard_after,"whole_service_future_memory_envelope_qualified":false,"shared_role_future_memory_envelopes_qualified":false,"all_current_and_future_shared_roles_still_charged":true,"current_guard_protection_is_not_future_memory_bound":true,"host_before":host_before,"host_after":host_after,"producer_before":before,"producer_after":after,"persistent_background_before":background_before,"persistent_background_after":background_after,"per_producer_fulfilled":credits,"complete_hard_memory_promises_preserved_bytes":BASE_MEMORY,"complete_DATA_promises_preserved_bytes":CURRENT_DATA,"current_observer_sample_unix_seconds":sampled,"corrected_conservative_authority":plan["current_complete_authority"],"conservative_memory_add_back_already_selected_bytes":ADD_BACK_MEMORY,"conservative_DATA_add_back_already_selected_bytes":ADD_BACK_DATA,"retained_verifier_pool_bytes":96*GIB,"retained_native_pool_bytes":16*GIB,"retained_shared_pool_bytes":64*GIB,"normal_pool_bytes":10*GIB,"effective_consumer_and_guard_accounting_authority_granted":false,"candidate_additive_hard_memory_bytes":candidate,"additional_host_headroom_bytes":16*GIB,"already_resident_nonreclaimable_anonymous_bytes_counted_in_those_caps":total,"source_qualified_kernel_counter_contract":counter_semantics,"historical_true_host_component_provenance":host_component,"kernel_identity_before":kernel_before,"kernel_identity_after":kernel_after,"per_host_kernel_fulfilled":kernel_consumption,"already_resident_unique_disjoint_components_total_bytes":disjoint_consumed,"required_available_memory_without_host_kernel_fulfillment_bytes":without_kernel,"candidate_fits_without_host_kernel_fulfillment":available>=without_kernel,"host_or_uploader_future_bound_qualified":false,"outside_input_pool_overlap_credited_bytes":0,"full_caps_plus_candidate_and_headroom_bytes":full,"required_available_memory_for_remaining_growth_bytes":remaining,"conservative_available_memory_bytes":available,"candidate_fits_this_native_sample":available>=remaining,"kernel_zero_swap_anon_semantics_only":false,"zero_swap_anon_and_disjoint_kernel_semantics_only":true,"RSS_file_cache_shared_pages_and_other_cgroup_anon_credited_bytes":0,"new_memory_or_DATA_promise_bytes":0,"resource_credit_bytes":0,"hard_promises_released_bytes":0,"physical_credit_bytes":0,"native_Frame_or_full_Reader_authority":false,"replay_launch_authorized":false,"producer_mutations":false,"remote_mutations":false,"new_resource_observations":true,"observation_reason":"admission-qualification","routine_observation_cadence_reset":false}),
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
        image == Path::new(IMAGE) && sha(&bytes(&image, 32 << 20, false)?) == a[5],
        "normally sealed self image required"
    );
    let plan = bound(&json!({"path":a[1],"sha256":a[3]}))?;
    let report = run(&plan)?;
    let output = Path::new(s(&plan, "output")?);
    let parent = output.parent().context("output parent")?;
    let m = fs::symlink_metadata(parent)?;
    ensure!(
        parent.canonicalize()? == parent && m.is_dir() && m.uid() == 0 && m.mode() & 0o077 == 0,
        "private output parent required"
    );
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(NOFOLLOW | CLOEXEC)
        .open(output)?;
    serde_json::to_writer_pretty(&mut f, &report)?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    File::open(parent)?.sync_all()?;
    println!(
        "{}",
        json!({"output":output,"candidate_fits_this_native_sample":report["candidate_fits_this_native_sample"],"resource_credit_bytes":0,"replay_launch_authorized":false})
    );
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cgroup_parser_rejects_duplicate_missing_and_fractional_anon() {
        assert_eq!(counter("anon 42\nfile 999999\n", "anon").unwrap(), 42);
        assert!(counter("anon 1\nanon 2\n", "anon").is_err());
        assert!(counter("file 1\n", "anon").is_err());
        assert!(counter("anon 1.5\n", "anon").is_err());
    }
    #[test]
    fn host_parser_requires_exact_units_no_overflow_and_valid_available() {
        assert_eq!(
            meminfo("MemTotal: 100 kB\nMemAvailable: 60 kB\n").unwrap(),
            (102400, 61440)
        );
        for raw in [
            "MemTotal: 100 MB\nMemAvailable: 60 kB\n",
            "MemTotal: 100 kB\nMemAvailable: 200 kB\n",
            "MemTotal: 18446744073709551615 kB\nMemAvailable: 1 kB\n",
            "MemTotal: 100 kB\nMemAvailable: 2 kB\nMemAvailable: 3 kB\n",
        ] {
            assert!(meminfo(raw).is_err());
        }
    }
    #[test]
    fn fulfilled_is_the_smaller_anon_endpoint_minus_an_extra_margin() {
        assert_eq!(fulfilled(9 * GIB, 8 * GIB, CAP).unwrap(), 7 * GIB);
        assert_eq!(fulfilled(GIB / 2, GIB, CAP).unwrap(), 0);
        assert!(fulfilled(CAP + 1, CAP, CAP).is_err());
        assert!(fulfilled(GIB, GIB, CAP + 1).is_err());
    }
    #[test]
    fn hard_promises_stay_intact_while_remaining_growth_counts_consumed_bytes_once() {
        assert_eq!(required(200, 30, 10, 20).unwrap(), 220);
        assert_eq!(required(200, 30, 10, 0).unwrap(), 240);
        assert!(required(u64::MAX, 1, 0, 0).is_err());
        assert!(required(1, 1, 1, 4).is_err());
    }
    #[test]
    fn file_cache_alone_never_counts_as_fulfilled() {
        let anon = counter("anon 0\nfile 18446744073709551615\n", "anon").unwrap();
        assert_eq!(fulfilled(anon, anon, CAP).unwrap(), 0);
    }
    #[test]
    fn only_the_qualified_purposes_can_run() {
        assert!(own_unit(&json!({"purpose":"qualification"})).is_ok());
        assert!(own_unit(&json!({"purpose":"epoch173-admission-check"})).is_ok());
        assert!(own_unit(&json!({"purpose":"replay"})).is_err());
    }
    #[test]
    fn candidate173_keeps_actor_guard_and_host_headroom_exact() {
        let p = json!({"candidate_epoch":173,"candidate_actor_memory_bytes":68*GIB,"candidate_guard_memory_bytes":GIB,"additional_host_headroom_bytes":16*GIB});
        assert_eq!(candidate_memory(&p).unwrap(), 69 * GIB);
        for (key, value) in [
            ("candidate_epoch", 171),
            ("candidate_actor_memory_bytes", 67 * GIB),
            ("candidate_guard_memory_bytes", 0),
            ("additional_host_headroom_bytes", 15 * GIB),
        ] {
            let mut bad = p.clone();
            bad[key] = json!(value);
            assert!(candidate_memory(&bad).is_err());
        }
    }
    #[test]
    fn unused_return_keeps_raw_fleet_and_cannot_be_applied_twice() {
        let m = LEGACY_BASE_MEMORY + 32 * GIB;
        assert!(returned_projection(m, LEGACY_BASE_DATA, 32 * GIB).is_ok());
        assert!(returned_projection(LEGACY_BASE_MEMORY, LEGACY_BASE_DATA, 32 * GIB).is_err());
        assert!(returned_projection(m, LEGACY_BASE_DATA - 1, 32 * GIB).is_err());
        assert!(returned_projection(m, LEGACY_BASE_DATA, 0).is_err());
        assert!(returned_projection(m, LEGACY_BASE_DATA, 16 * GIB).is_err());
    }
    fn current_fixture() -> (Value, Value) {
        (
            json!({"schema":"horizon-existing-singleton173-metadata-preparation-v1","complete_projected_memory_bytes":DISPUTED_MEMORY,"complete_DATA_bytes":DISPUTED_DATA,"new_memory_promise_bytes":0,"new_retained_DATA_bytes":64u64<<20,"previous_complete_DATA_bytes":6_100_989_591_346u64,"normal_pool_bytes":10*GIB}),
            json!({"schema":"horizon-fresh-standard172-resource-admission-v1","owner":"/root","primary_thread":PRIMARY,"complete_projected_memory_bytes":DISPUTED_MEMORY,"complete_DATA_bytes":6_100_989_591_346u64,"previous_complete_DATA_bytes":LEGACY_BASE_DATA,"candidate_own_DATA_bytes":309_237_645_312u64,"candidate_guard_metadata_DATA_bytes":8*GIB,"all_existing_hard_memory_promises_retained":true,"all_previous_once_only_endings_preserved_without_reapplication":true,"proven_replay_count":6,"one_additional_guarded_lane_experiment":true,"normal_pool_bytes":10*GIB}),
        )
    }
    #[test]
    fn current173_preparation_adds_only64_mib_and_never_reapplies_an_ending() {
        let (p, a) = current_fixture();
        assert!(current_projection(&p, &a).is_ok());
        for (k, v) in [
            (
                "complete_projected_memory_bytes",
                json!(DISPUTED_MEMORY - 32 * GIB),
            ),
            ("complete_DATA_bytes", json!(DISPUTED_DATA - 1)),
            ("new_memory_promise_bytes", json!(GIB)),
            ("new_retained_DATA_bytes", json!(32u64 << 20)),
        ] {
            let mut p = p.clone();
            p[k] = v;
            assert!(current_projection(&p, &a).is_err(), "{k}");
        }
    }
    #[test]
    fn current173_keeps_original172_actor_guard_and_prior_hard_promises() {
        let (p, a) = current_fixture();
        for (k, v) in [
            ("complete_projected_memory_bytes", json!(LEGACY_BASE_MEMORY)),
            ("all_existing_hard_memory_promises_retained", json!(false)),
            (
                "all_previous_once_only_endings_preserved_without_reapplication",
                json!(false),
            ),
            ("candidate_guard_metadata_DATA_bytes", json!(0)),
            ("candidate_own_DATA_bytes", json!(1)),
        ] {
            let mut a = a.clone();
            a[k] = v;
            assert!(current_projection(&p, &a).is_err(), "{k}");
        }
    }
    fn conservative_fixture() -> (Value, Value, Value, Value) {
        let corrected: Value=serde_json::from_str(r#"{"primary_thread":"01a1af2a-9ce8-76a2-8939-b2112bd38f53","owner":"/root","schema":"horizon-Root-conservative-duplicate722-addback-current-authority-v1","current_extra_QA_memory_bytes":0,"actual_native_audit_drain":{"path":"/home/sol/.jetstreamer-private/epoch173-independent-singleton-20261110-v1/duplicate722-authority-audit-qa-v2/ROOT_NATIVE_AUDIT_DRAINED_CONSERVATIVE_CORRECTION_NOT_YET_SELECTED.json","sha256":"b2a4c4c70e749d6c620a45a14eabeed2867f97052b67779e6917fccef411236d"},"physical_or_holding_credit_bytes":0,"first_original_ending_retained_once":true,"new_memory_or_DATA_credit_bytes":0,"normal_pool_bytes":10737418240,"complete_projected_memory_bytes":759789531136,"all_verifier96_native16_shared64_pools_retained":true,"all_original_receipts_and_raw_histories_retained":true,"duplicate_original_invocation_id":"722adc397ae24bb4b96d452783599f57","old_head_disputed_and_superseded_for_current_accounting":true,"producer_or_guard_mutations":false,"native_Frame_or_full_Reader_acceptance_claimed":false,"complete_DATA_bytes":6582025928498,"existing_native16_pool_bytes":17179869184,"second_original_actor_and_DATA_deduction_counteracted_conservatively":true,"existing_all_seven_hard_caps_unchanged":true,"previous_complete_projected_memory_bytes":708249923584,"selected_new_release_bytes":0,"restored_conservative_actor48_bytes":51539607552,"replay_admission_authorized":false,"new_memory_promise_bytes":0,"previous_complete_DATA_bytes":6101056700210,"restored_conservative_future_DATA_bytes":480969228288,"existing_all_seven_producers_preserved":true,"remote_mutations":false,"genuine_native_duplicate_ending_audit":{"path":"/home/sol/.jetstreamer-private/epoch173-independent-singleton-20261110-v1/duplicate722-authority-audit-qa-v2/ACTUAL_DUPLICATE722_AUTHORITY_AUDIT.json","sha256":"b462365e124649771596844998dafb87c4f403466cf3fb5beb410d2f75fbf751"}}"#).unwrap();
        let audit: Value=serde_json::from_str(r#"{"primary_thread":"01a1af2a-9ce8-76a2-8939-b2112bd38f53","owner":"/root","schema":"horizon-duplicate722-authority-audit-report-v1","recommended_conservative_DATA_add_back_bytes":480969228288,"proposed_corrected_complete_DATA_bytes":6582025928498,"authority_selection_performed":false,"proposed_corrected_complete_projected_memory_bytes":759789531136,"effective_memory_rebooking_in_complete_selected_chain":false,"all_original_receipts_must_be_preserved":true,"verification96_bytes_still_retained":103079215104,"producer_guard_timer_mutations":false,"same_original_future_DATA_ending_selected_twice":true,"native_self":{"ActiveState":"active","ControlGroup":"/system.slice/horizon-duplicate722-authority-audit-20261110-v2.service","ControlPID":"0","Delegate":"no","ExecMainStatus":"0","Id":"horizon-duplicate722-authority-audit-20261110-v2.service","InvocationID":"f74a1c6af7234c19b0cf3e99209db160","Job":"","KillMode":"control-group","LoadState":"loaded","MainPID":"584394","MemoryAccounting":"yes","MemoryMax":"536870912","MemorySwapMax":"0","NRestarts":"0","Restart":"no","Result":"success","SubState":"running","Type":"exec"},"new_resource_credit_bytes":0,"same_original_actor48_ending_selected_twice":true,"native16_bytes_still_retained":17179869184,"shared64_bytes_still_retained":68719476736,"replay_admission_authorized":false,"first_ending_consumed_by_actual170":true,"recommended_conservative_memory_add_back_bytes":51539607552,"ancestry_nodes":45,"large_DATA_rebooking_in_complete_selected_chain":false,"remote_mutations":false}"#).unwrap();
        let drain: Value=serde_json::from_str(r#"{"selection_performed":false,"new_credit_bytes":0,"native_pool_bytes":17179869184,"healthy_producers_untouched":true,"actual_audit":{"path":"/home/sol/.jetstreamer-private/epoch173-independent-singleton-20261110-v1/duplicate722-authority-audit-qa-v2/ACTUAL_DUPLICATE722_AUTHORITY_AUDIT.json","sha256":"b462365e124649771596844998dafb87c4f403466cf3fb5beb410d2f75fbf751"},"native":{"MainPID":"0","ControlPID":"0","Result":"success","NRestarts":"0","ExecMainStatus":"0","ActiveState":"inactive","SubState":"dead"}}"#).unwrap();
        (corrected, current_fixture().0, audit, drain)
    }
    #[test]
    fn conservative_head_adds_back_both_duplicate_deductions_once() {
        let (c, o, a, d) = conservative_fixture();
        assert!(conservative_projection(&c, &o, &a, &d).is_ok());
        assert_eq!(BASE_MEMORY, DISPUTED_MEMORY + ADD_BACK_MEMORY);
        assert_eq!(BASE_DATA, DISPUTED_DATA + ADD_BACK_DATA);
        assert_eq!(
            required(BASE_MEMORY, 69 * GIB, 16 * GIB, 0).unwrap(),
            BASE_MEMORY + 85 * GIB
        );
    }
    #[test]
    fn missing_repeated_or_reapplied_addback_is_rejected() {
        let (c, o, a, d) = conservative_fixture();
        for (k, v) in [
            ("restored_conservative_actor48_bytes", json!(0)),
            (
                "restored_conservative_actor48_bytes",
                json!(2 * ADD_BACK_MEMORY),
            ),
            ("restored_conservative_future_DATA_bytes", json!(0)),
            (
                "restored_conservative_future_DATA_bytes",
                json!(2 * ADD_BACK_DATA),
            ),
            (
                "complete_projected_memory_bytes",
                json!(BASE_MEMORY + ADD_BACK_MEMORY),
            ),
            ("complete_DATA_bytes", json!(BASE_DATA + ADD_BACK_DATA)),
            ("first_original_ending_retained_once", json!(false)),
        ] {
            let mut bad = c.clone();
            bad[k] = v;
            assert!(conservative_projection(&bad, &o, &a, &d).is_err(), "{k}");
        }
        assert!(conservative_projection(&c, &c, &a, &d).is_err());
        let mut old = o;
        old["complete_projected_memory_bytes"] = json!(DISPUTED_MEMORY - 1);
        assert!(conservative_projection(&c, &old, &a, &d).is_err());
    }
    #[test]
    fn changed_native_audit_pools_or_drain_never_qualify_the_head() {
        let (c, o, a, d) = conservative_fixture();
        for (k, v) in [
            ("same_original_actor48_ending_selected_twice", json!(false)),
            ("first_ending_consumed_by_actual170", json!(false)),
            ("recommended_conservative_memory_add_back_bytes", json!(0)),
            (
                "effective_memory_rebooking_in_complete_selected_chain",
                json!(true),
            ),
            ("shared64_bytes_still_retained", json!(24 * GIB)),
            ("verification96_bytes_still_retained", json!(64 * GIB)),
            ("native16_bytes_still_retained", json!(8 * GIB)),
        ] {
            let mut bad = a.clone();
            bad[k] = v;
            assert!(conservative_projection(&c, &o, &bad, &d).is_err(), "{k}");
        }
        let mut bad = a;
        bad["native_self"]["InvocationID"] = json!("e".repeat(32));
        assert!(conservative_projection(&c, &o, &bad, &d).is_err());
        let mut bad = d;
        bad["native"]["MainPID"] = json!("1");
        assert!(conservative_projection(&c, &o, &conservative_fixture().2, &bad).is_err());
    }
    #[test]
    fn changed_correction_or_audit_digest_cannot_select_an_altered_head() {
        let (c, o, a, d) = conservative_fixture();
        assert!(
            exact_binding(
                &json!({"path":CORRECTION_PATH,"sha256":CORRECTION_SHA}),
                CORRECTION_PATH,
                CORRECTION_SHA
            )
            .is_ok()
        );
        assert!(
            exact_binding(
                &json!({"path":CORRECTION_PATH,"sha256":"f".repeat(64)}),
                CORRECTION_PATH,
                CORRECTION_SHA
            )
            .is_err()
        );
        let mut bad = c;
        bad["genuine_native_duplicate_ending_audit"]["sha256"] = json!("f".repeat(64));
        assert!(conservative_projection(&bad, &o, &a, &d).is_err());
    }
    fn fresh_fleet_fixture() -> (Value, Value, Value, u64) {
        let authority = json!({"path":HEAD_PATH,"sha256":HEAD_SHA});
        let fleet = json!({"schema":"horizon-Root-complete-fleet-operational-review-v1","owner":"/root","primary_thread":PRIMARY,"live_replay_count":7,"active_producer_count":7,"proven_replay_count":7,"guarded_bootstrap_owner_count":0,"complete_projected_memory_bytes":BASE_MEMORY,"complete_DATA_bytes":CURRENT_DATA,"normal_pool_bytes":10*GIB,"complete_DATA_authority":authority,"sampled_at_utc":"2026-11-10T09:30:22Z"});
        let observer = json!({"schema":"jetstreamer-horizon-live-resource-sample-v2","recorded_at_utc":"2026-11-10T09:30:22Z","completed_at_utc":"2026-11-10T09:31:30Z"});
        (
            fleet,
            observer,
            json!({"current_complete_authority":authority}),
            utc_seconds("2026-11-10T09:30:22Z").unwrap(),
        )
    }
    #[test]
    fn freshness_uses_exact_observer_clock_and_rejects_stale_future_or_mismatched_sample() {
        let (f, o, p, t) = fresh_fleet_fixture();
        assert_eq!(fleet_context(&f, &o, &p, t + 68).unwrap(), t);
        assert!(fleet_context(&f, &o, &p, t + 1800).is_ok());
        assert!(fleet_context(&f, &o, &p, t + 1801).is_err());
        assert!(fleet_context(&f, &o, &p, t - 1).is_err());
        let mut stale = o.clone();
        stale["recorded_at_utc"] = json!("2026-11-10T06:00:22Z");
        assert!(fleet_context(&f, &stale, &p, t + 68).is_err());
        let mut crossed = f.clone();
        crossed["sampled_at_utc"] = json!("2026-11-10T09:00:22Z");
        assert!(fleet_context(&crossed, &o, &p, t + 68).is_err());
        let mut old = f;
        old["complete_projected_memory_bytes"] = json!(DISPUTED_MEMORY);
        assert!(fleet_context(&old, &o, &p, t + 68).is_err());
    }
    #[test]
    fn strict_utc_handles_leap_boundaries_and_rejects_invalid_calendar_or_units() {
        assert_eq!(utc_seconds("1970-01-01T00:00:00Z").unwrap(), 0);
        assert_eq!(
            utc_seconds("2024-03-01T00:00:00Z").unwrap()
                - utc_seconds("2024-02-28T00:00:00Z").unwrap(),
            2 * 86400
        );
        assert_eq!(utc_seconds("2026-11-10T09:30:22Z").unwrap(), 1794303022);
        for bad in [
            "2026-02-29T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-11-10T24:00:00Z",
            "2026-11-10T09:30:60Z",
            "2026-11-10 09:30:22Z",
            "2026-11-10T09:30:22+00:00",
        ] {
            assert!(utc_seconds(bad).is_err(), "{bad}");
        }
    }
    fn kernel_fixture(sun: u64, stack: u64, pages: u64, percpu: u64, reclaim: u64) -> String {
        format!(
            "MemTotal: 1000000000 kB\nMemAvailable: 500000000 kB\nSlab: {} kB\nSReclaimable: {} kB\nSUnreclaim: {} kB\nKernelStack: {} kB\nPageTables: {} kB\nPercpu: {} kB\n",
            (sun + reclaim) / 1024,
            reclaim / 1024,
            sun / 1024,
            stack / 1024,
            pages / 1024,
            percpu / 1024
        )
    }
    #[test]
    fn host_kernel_parser_counts_only_disjoint_nonreclaimable_fields() {
        let v = meminfo_kernel(&kernel_fixture(10 * GIB, GIB, 2 * GIB, 3 * GIB, 40 * GIB)).unwrap();
        assert_eq!(v["kernel_components_bytes"]["SUnreclaim"], 10 * GIB);
        assert_eq!(v["excluded_reclaimable_slab_bytes"], 40 * GIB);
        assert_eq!(v["whole_slab_not_credited_bytes"], 50 * GIB);
        assert_eq!(v["kernel_components_bytes"].as_object().unwrap().len(), 3);
    }
    #[test]
    fn reclaimable_slab_and_file_cache_alone_never_fulfill_the_host_component() {
        let raw = kernel_fixture(0, 0, 0, 0, 50 * GIB)
            + "Cached: 999999999 kB\nKReclaimable: 999999999 kB\nVmallocUsed: 999999999 kB\n";
        let v = meminfo_kernel(&raw).unwrap();
        let f = kernel_fulfilled(&v, &v, TRUE_HOST_COMPONENT).unwrap();
        assert_eq!(f["already_consumed_kernel_bytes"], 0);
        assert_eq!(f["outside_input_component_counted_bytes"], 0);
        assert_eq!(f["shared_native_verifier_or_actor_kernel_credit_bytes"], 0);
    }
    #[test]
    fn kernel_parser_rejects_duplicate_missing_wrong_units_and_bad_same_local_split() {
        let raw = kernel_fixture(GIB, GIB, GIB, GIB, GIB);
        for bad in [
            raw.clone() + "SUnreclaim: 1 kB\n",
            raw.replace("Percpu: 1048576 kB\n", ""),
            raw.replace("PageTables: 1048576 kB", "PageTables: 1048576 MB"),
            raw.replace("Slab: 2097152 kB", "Slab: 2097153 kB"),
            raw.replace(
                "SUnreclaim: 1048576 kB",
                "SUnreclaim: 18446744073709551615 kB",
            ),
        ] {
            assert!(meminfo_kernel(&bad).is_err());
        }
    }
    #[test]
    fn kernel_consumption_uses_each_smaller_endpoint_and_separate_margin() {
        let a = meminfo_kernel(&kernel_fixture(10 * GIB, 3 * GIB, 2 * GIB, GIB, 8 * GIB)).unwrap();
        let b = meminfo_kernel(&kernel_fixture(8 * GIB, GIB, 4 * GIB, 2 * GIB, 9 * GIB)).unwrap();
        let f = kernel_fulfilled(&a, &b, TRUE_HOST_COMPONENT).unwrap();
        assert_eq!(f["pre_margin_unique_kernel_bytes"], 11 * GIB);
        assert_eq!(f["already_consumed_kernel_bytes"], 10 * GIB);
        assert_eq!(f["global_component_minima_bytes"]["PageTables"], 2 * GIB);
    }
    #[test]
    fn global_and_child_kernel_counters_cannot_both_enter_the_ledger() {
        let good = meminfo_kernel(&kernel_fixture(GIB, GIB, GIB, GIB, GIB)).unwrap();
        for key in [
            "Slab",
            "SReclaimable",
            "KReclaimable",
            "VmallocUsed",
            "Percpu",
            "kernel",
            "child/actor166/pagetables",
        ] {
            let mut bad = good.clone();
            bad["kernel_components_bytes"][key] = json!(GIB);
            assert!(
                kernel_fulfilled(&bad, &good, TRUE_HOST_COMPONENT).is_err(),
                "{key}"
            );
        }
        let mut missing = good.clone();
        missing["kernel_components_bytes"]
            .as_object_mut()
            .unwrap()
            .remove("KernelStack");
        assert!(kernel_fulfilled(&missing, &good, TRUE_HOST_COMPONENT).is_err());
    }
    #[test]
    fn host_consumption_cannot_fulfill_input_overlap_or_exceed_the_true_component() {
        let v = meminfo_kernel(&kernel_fixture(100 * GIB, GIB, GIB, GIB, GIB)).unwrap();
        let f = kernel_fulfilled(&v, &v, TRUE_HOST_COMPONENT).unwrap();
        assert_eq!(f["already_consumed_kernel_bytes"], TRUE_HOST_COMPONENT);
        assert!(kernel_fulfilled(&v, &v, TRUE_HOST_COMPONENT + OUTSIDE_INPUT_COMPONENT).is_err());
        assert_eq!(f["unfulfilled_host_component_bytes"], 0);
        assert_eq!(f["resource_credit_bytes"], 0);
        assert_eq!(f["hard_promises_released_bytes"], 0);
    }
    #[test]
    fn zero_kernel_fulfillment_exactly_preserves_v12_anonymous_only_arithmetic() {
        let v = meminfo_kernel(&kernel_fixture(0, 0, 0, 0, 0)).unwrap();
        let f = kernel_fulfilled(&v, &v, TRUE_HOST_COMPONENT).unwrap();
        let anon = 50 * GIB;
        let kernel = n(&f, "already_consumed_kernel_bytes").unwrap();
        assert_eq!(
            required(
                BASE_MEMORY,
                69 * GIB,
                16 * GIB,
                sum_checked([anon, kernel]).unwrap()
            )
            .unwrap(),
            required(BASE_MEMORY, 69 * GIB, 16 * GIB, anon).unwrap()
        );
        assert_eq!(BASE_MEMORY, 759_789_531_136);
        assert_eq!(CURRENT_DATA, 6_229_838_610_226);
    }
    #[test]
    fn kernel_identity_rejects_unsupported_release_malformed_boot_or_replacement() {
        let boot = "763ea84c-a81f-4ddd-ad36-4b1ea2ba36dd";
        assert!(kernel_identity_shape("6.8.0-149-generic", boot, "x86_64").is_ok());
        assert!(kernel_identity_shape("6.8.0-146-generic", boot, "x86_64").is_ok());
        assert!(kernel_identity_shape("6.9.0-generic", boot, "x86_64").is_err());
        assert!(kernel_identity_shape("6.8.0-149-generic", "wrong", "x86_64").is_err());
        let a = json!({"release":"6.8.0-149-generic","boot_id":boot,"machine":"x86_64"});
        let b = json!({"release":"6.8.0-149-generic","boot_id":"00000000-0000-0000-0000-000000000001","machine":"x86_64"});
        assert!(same_kernel(&a, &b).is_err());
        assert!(kernel_identity_shape("6.8.0-149-generic", boot, "aarch64").is_err());
    }
    #[test]
    fn data_only_head_never_drops_memory_pools_or_reapplies_a_memory_ending() {
        let head:Value=serde_json::from_str(r#"{"producer_guard_timer_mutations":false,"new_memory_credit_bytes":0,"schema":"horizon-Root-once-only-original154-unused-future-DATA-selection-authority-v1","retained_shared_pool_bytes":68719476736,"remote_mutations":false,"previous_complete_DATA_bytes":6582025928498,"primary_thread":"01a1af2a-9ce8-76a2-8939-b2112bd38f53","normal_pool_bytes":10737418240,"old154_memory64_ending_reapplied_bytes":0,"additional_once_only_ended_unused_future_DATA_bytes":352187318272,"effective_verification_pool_bytes":103079215104,"all_seven_original_producers_and_caps_preserved":true,"all_previous_once_only_endings_retained_without_reapplication":true,"replay_admission_authorized":false,"complete_DATA_bytes":6229838610226,"native_Frame_or_full_Reader_acceptance_claimed":false,"owner":"/root","complete_projected_memory_bytes":759789531136,"retained_native16_pool_bytes":17179869184}"#).unwrap();
        assert!(current_head_projection(&head).is_ok());
        for (k, v) in [
            ("complete_projected_memory_bytes", json!(BASE_MEMORY - GIB)),
            ("new_memory_credit_bytes", json!(GIB)),
            ("retained_shared_pool_bytes", json!(63 * GIB)),
            ("old154_memory64_ending_reapplied_bytes", json!(64 * GIB)),
            (
                "native_Frame_or_full_Reader_acceptance_claimed",
                json!(true),
            ),
            (
                "complete_DATA_bytes",
                json!(CURRENT_DATA - 352_187_318_272u64),
            ),
        ] {
            let mut bad = head.clone();
            bad[k] = v;
            assert!(current_head_projection(&bad).is_err(), "{k}");
        }
        assert!(
            exact_binding(
                &json!({"path":HEAD_PATH,"sha256":"f".repeat(64)}),
                HEAD_PATH,
                HEAD_SHA
            )
            .is_err()
        );
    }
    #[test]
    fn percpu_remains_diagnostic_until_its_managed_ram_scope_is_independently_proven() {
        let v = meminfo_kernel(&kernel_fixture(0, 0, 0, 100 * GIB, 0)).unwrap();
        assert_eq!(v["diagnostic_only_Percpu_bytes"], 100 * GIB);
        let f = kernel_fulfilled(&v, &v, TRUE_HOST_COMPONENT).unwrap();
        assert_eq!(f["already_consumed_kernel_bytes"], 0);
        assert!(v["kernel_components_bytes"].get("Percpu").is_none());
    }
}
