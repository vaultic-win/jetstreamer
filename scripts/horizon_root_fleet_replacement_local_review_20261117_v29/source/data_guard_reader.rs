//! Read-only shared consumer for a normally sealed DATA guard successor.
//! The historical first guard remains under its original pin. This module grants no handoff,
//! admission, promise ending, replay, publication, deletion or resource-credit authority.
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fs::{self, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};
#[path = "interrupted_recovery.rs"]
mod interrupted_recovery;
pub type R<T> = Result<T, Box<dyn Error>>;
pub const FLOOR: u64 = 6_264_131_239_730;
const DATA: u64 = 6_229_838_610_226;
const CAP: u64 = 309_237_645_312;
const MAXIMUM: u64 = 241_482_399_744;
const OLD: &str = "35dbd4826c8947f38d50dff049345e1c3d62450eb85e41e94e326880e1898fbc";
const PRIMARY: &str = "01a1af2a-9ce8-76a2-8939-b2112bd38f53";
const SEALER: &str = "e0d565f4450b25b527ffd4455a52e1861568548b826e86a6894a1ae127e811f3";
const HEAD: &str = "/usr/local/lib/jetstreamer/horizon-original154-future-data-current-authority-20261110-v1/authority.json";
const ANCESTRY: &str = "/home/sol/.jetstreamer-private/epoch173-independent-singleton-20261110-v1/original154-future-data-qa-v2/ACTUAL_ORIGINAL154_FUTURE_DATA_CHECK.json";
const ANCESTRY_SHA: &str = "03a9fe761e5ce4aa4d694abc0cdbb59db9c29b898442334e9c2d3c556bfab399";
const MANIFEST: &str = "/usr/local/lib/jetstreamer/horizon-original154-future-data-source-20261110-v2/lineage-manifest.json";
const MANIFEST_SHA: &str = "4906d22bdcc5656c2f28da7a9a28d45496c65ca57fc13cf898382b09a514b505";
const HEAD_SHA: &str = "2f88b7f91cc6df70804cd96027efbd0e18cb6452a48e76d813673b556d727caa";
pub struct Context<'a> {
    pub epoch: u64,
    pub unit: &'a str,
    pub iid: &'a str,
    pub pid: u64,
    pub start: u64,
    pub original_protection: &'a Value,
}
pub struct Accepted {
    pub protection: Value,
    pub plan: Value,
    pub runtime: Value,
    pub registration: Value,
    pub native_witness: Value,
    pub handoff: Value,
}
fn need(ok: bool, msg: &str) -> R<()> {
    if ok { Ok(()) } else { Err(msg.into()) }
}
fn s<'a>(v: &'a Value, k: &str) -> R<&'a str> {
    v[k].as_str().ok_or_else(|| format!("missing {k}").into())
}
fn n(v: &Value, k: &str) -> R<u64> {
    v[k].as_u64()
        .ok_or_else(|| format!("missing integer {k}").into())
}
fn hex(v: &str, len: usize) -> bool {
    v.len() == len
        && v.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && v.bytes().any(|b| b != b'0')
}
fn sha(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
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
fn bytes(path: &Path, immutable: bool) -> R<Vec<u8>> {
    need(
        path.is_absolute() && path.canonicalize()? == path,
        "canonical bound metadata required",
    )?;
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(0x20000 | 0x80000)
        .open(path)?;
    let m = f.metadata()?;
    need(
        m.is_file()
            && m.uid() == 0
            && m.nlink() == 1
            && m.mode() & 0o022 == 0
            && m.len() <= 32 << 20
            && (!immutable || m.mode() & 0o7777 == 0o444 || m.mode() & 0o7777 == 0o555),
        "unsafe bound metadata",
    )?;
    let mut out = Vec::new();
    Read::by_ref(&mut f)
        .take((32 << 20) + 1)
        .read_to_end(&mut out)?;
    need(
        out.len() as u64 == m.len()
            && identity(&m) == identity(&f.metadata()?)
            && identity(&m) == identity(&fs::symlink_metadata(path)?),
        "bound metadata changed",
    )?;
    Ok(out)
}
fn bound(b: &Value) -> R<Value> {
    let hash = s(b, "sha256")?;
    need(hex(hash, 64), "exact SHA binding required")?;
    let raw = bytes(Path::new(s(b, "path")?), false)?;
    need(sha(&raw) == hash, "bound digest differs")?;
    Ok(serde_json::from_slice(&raw)?)
}
fn normal(member: &Value, seal: &Value, name: &str, mode: &str) -> R<Value> {
    let path = Path::new(s(member, "path")?);
    let parent = path.parent().ok_or("member parent")?;
    need(
        path.file_name().is_some_and(|v| v == name)
            && Path::new(s(seal, "path")?) == parent.join("deployment-seal-receipt.json"),
        "normal member/seal namespace required",
    )?;
    let raw = bytes(path, true)?;
    need(
        fs::symlink_metadata(path)?.mode() & 0o7777 == u32::from_str_radix(mode, 8)?,
        "normal sealed member mode changed",
    )?;
    need(sha(&raw) == s(member, "sha256")?, "sealed member changed")?;
    let proof = bound(seal)?;
    let members = proof["members"].as_array().ok_or("normal members")?;
    let selected = members
        .iter()
        .filter(|v| v["name"] == name)
        .collect::<Vec<_>>();
    need(
        proof["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && proof["sealer_sha256"] == SEALER
            && proof["destination"] == parent.to_str().ok_or("UTF8 parent")?
            && proof["replay_launch_authorized"] == false
            && proof["remote_mutations"] == false
            && selected.len() == 1
            && selected[0]["sha256"] == member["sha256"]
            && selected[0]["mode"] == mode,
        "normal seal/image registration differs",
    )?;
    if mode == "0555" {
        Ok(Value::Null)
    } else {
        Ok(serde_json::from_slice(&raw)?)
    }
}
fn owner(v: &Value, c: &Context<'_>) -> R<()> {
    need(
        v["Id"] == c.unit
            && v["InvocationID"] == c.iid
            && v["MainPID"].as_str().and_then(|p| p.parse::<u64>().ok()) == Some(c.pid)
            && v["ControlPID"] == "0"
            && v["NRestarts"] == "0"
            && v["ActiveState"] == "active"
            && v["SubState"] == "running"
            && v["Job"] == "",
        "actual producer identity/restart changed",
    )
}
fn timer(t: &Value, p: &Value) -> R<()> {
    need(
        t["Id"] == p["timer_unit"]
            && t["InvocationID"] == p["timer_invocation_id"]
            && t["LoadState"] == "loaded"
            && t["ActiveState"] == "active"
            && matches!(
                t["SubState"].as_str(),
                Some("waiting" | "running" | "elapsed")
            )
            && t["Triggers"] == p["guard_unit"]
            && t["Job"] == "",
        "exact new protective timer required",
    )
}
fn terminal(v: &Value, unit: &Value, service: bool) -> R<()> {
    need(
        v["Id"] == *unit
            && matches!(v["LoadState"].as_str(), Some("loaded" | "not-found"))
            && v["ActiveState"] == "inactive"
            && v["SubState"] == "dead"
            && v["Job"] == "",
        "old guard not drained",
    )?;
    if service {
        need(
            v["MainPID"] == "0"
                && v["ControlPID"] == "0"
                && v["NRestarts"] == "0"
                && v["ControlGroup"] == "",
            "old guard service still owns work",
        )?;
    }
    Ok(())
}
fn allocation(a: &Value) -> R<(u64, u64)> {
    let rows = a["first"].as_array().ok_or("allocation first")?;
    need(
        rows.len() == 15 && a["first"] == a["second"],
        "complete stable finite witness set required",
    )?;
    let device = n(&a["filesystem_midpoint"], "device")?;
    let mut available = u64::MAX;
    for k in [
        "filesystem_before",
        "filesystem_midpoint",
        "filesystem_after",
    ] {
        need(
            n(&a[k], "device")? == device && a[k]["filesystem_magic"] == 0xef53,
            "qualified unshared ext filesystem required",
        )?;
        available = available.min(n(&a[k], "available_bytes")?);
    }
    let mut ids = BTreeSet::new();
    let mut paths = BTreeSet::new();
    let mut per_slot = BTreeMap::new();
    for f in rows {
        let e = n(f, "epoch")?;
        let path = Path::new(s(f, "path")?);
        let lane = format!("/home/sol/.jetstreamer-private/epoch{e}-standard-lane-20261109-v1");
        need(
            (166..=170).contains(&e)
                && path.starts_with(&lane)
                && path != Path::new(&lane)
                && paths.insert(path.to_path_buf())
                && n(f, "dev")? == device
                && n(f, "nlink")? == 1
                && ids.insert((device, n(f, "ino")?))
                && n(f, "uid")? == 1001
                && n(f, "gid")? == 1003
                && n(f, "mode")? & 0o170000 == 0o100000
                && n(f, "mode")? & 0o077 == 0
                && f["birth_seconds"].as_i64().is_some_and(|v| v > 0)
                && n(f, "birth_nanoseconds")? < 1_000_000_000
                && f["ancestors"].as_array().is_some_and(|v| !v.is_empty()),
            "witness identity/custody/type/alias/slot differs",
        )?;
        let count = per_slot.entry(e).or_insert(0u64);
        *count = count
            .checked_add(
                n(f, "allocated_blocks512")?
                    .checked_mul(512)
                    .ok_or("block overflow")?,
            )
            .ok_or("slot allocation overflow")?;
        need(*count <= CAP, "original cap exceeded")?;
    }
    need(
        per_slot.len() == 5,
        "all five exact represented original slots required",
    )?;
    let mut total = 0u64;
    for (e, v) in &mut per_slot {
        *v = v.saturating_sub(1 << 30);
        need(
            a["per_slot"][e.to_string()] == *v,
            "per-slot margin equation changed",
        )?;
        total = total.checked_add(*v).ok_or("fulfilled sum overflow")?;
    }
    need(
        a["per_slot"].as_object().is_some_and(|v| v.len() == 5)
            && n(a, "conservative_available_bytes")? == available
            && n(a, "conservative_fulfilled_bytes")? == total
            && total > 0
            && total <= MAXIMUM,
        "allocation total/free equation changed",
    )?;
    Ok((available, total))
}
/// All reads are metadata/image authenticity reads; witness measurement is performed by the guard.
fn registered_binding(binding: &Value, registry: &Value) -> R<()> {
    let entries = registry.as_array().ok_or("compiled DATA guard registry")?;
    need(
        entries.iter().filter(|v| *v == binding).count() == 1,
        "unknown/unregistered DATA guard image/registration envelope",
    )
}
pub fn registration(binding: &Value, clock: u64) -> R<Accepted> {
    let registry: Value = serde_json::from_str(include_str!("data-guard-registrations.json"))?;
    registered_binding(binding, &registry)?;
    let r = bound(binding)?;
    let registration_seal = r.get("registration_deployment_seal");
    // registration.json cannot contain its own seal digest. The outer binding carries that seal.
    need(
        registration_seal.is_none(),
        "registration must not carry circular self seal",
    )?;
    let seal = &binding["deployment_seal"];
    normal(binding, seal, "registration.json", "0444")?;
    need(
        r["schema"] == "horizon-local2-DATA-guard-registration-v1"
            && r["owner"] == "/root"
            && r["primary_thread"] == PRIMARY
            && r["raw_minimum_free_bytes"] == FLOOR
            && r["complete_DATA_bytes"] == DATA
            && r["full_original_root_cap_bytes"] == CAP
            && r["resource_credit_bytes"] == 0
            && r["DATA_ending_bytes"] == 0
            && r["replay_admission_authorized"] == false
            && r["guard_handoff_authorized"] == false
            && r["remote_mutations"] == false,
        "exact sealed DATA guard registration required",
    )?;
    let runtime = r["guard_runtime"].clone();
    need(
        runtime["sha256"] != OLD && hex(s(&runtime, "sha256")?, 64),
        "old or unknown successor image",
    )?;
    normal(
        &runtime,
        &r["guard_runtime_deployment_seal"],
        "jetstreamer-horizon-standalone-guard",
        "0555",
    )?;
    let q = bound(&r["source_qualification"])?;
    need(
        q["four_strict_configurations_passed"] == true
            && n(&q, "ordinary_tests_passed")? > 0
            && q["production_sha256"] == runtime["sha256"],
        "actual four-configuration qualification must bind runtime",
    )?;
    let contract = normal(
        &r["contract"],
        &r["contract_deployment_seal"],
        "contract.json",
        "0444",
    )?;
    let maximum = n(&contract, "maximum_fulfilled_bytes")?;
    need(
        contract["schema"] == "horizon-original-slot-DATA-guard-contract-v1"
            && maximum > 0
            && maximum <= MAXIMUM,
        "finite exact contract required",
    )?;
    let seed = normal(
        &contract["witness_set"],
        &contract["witness_set_deployment_seal"],
        "witness-set.json",
        "0444",
    )?;
    need(
        seed["schema"] == "horizon-original-slot-DATA-witness-set-v1"
            && seed["complete_authority"] == json!({"path":HEAD,"sha256":HEAD_SHA})
            && seed["owner"] == "/root"
            && seed["primary_thread"] == PRIMARY
            && seed["complete_DATA_bytes"] == DATA
            && seed["raw_minimum_free_bytes"] == FLOOR
            && seed["full_original_root_cap_bytes"] == CAP
            && seed["margin_per_credited_slot_bytes"] == (1u64 << 30)
            && seed["maximum_fulfillment_bytes"] == MAXIMUM,
        "original complete authority/witness promises changed",
    )?;
    bound(&seed["complete_authority"])?;
    need(
        seed["accepted_original154_ancestry"] == json!({"path":ANCESTRY,"sha256":ANCESTRY_SHA})
            && seed["lineage_manifest"] == json!({"path":MANIFEST,"sha256":MANIFEST_SHA}),
        "exact original seventy-node ancestry registration required",
    )?;
    bound(&seed["accepted_original154_ancestry"])?;
    bound(&seed["lineage_manifest"])?;
    let w = bound(&contract["qualified_native_witness"])?;
    need(
        w["schema"] == "horizon-original-slot-DATA-native-witness-qualification-v1"
            && w["owner"] == "/root"
            && w["primary_thread"] == PRIMARY
            && w["native_identity"]["executable"] == runtime["path"]
            && w["native_identity"]["executable_sha256"] == runtime["sha256"]
            && n(&w["native_identity"], "pid")? > 1
            && hex(s(&w["native_identity"], "systemd_invocation_id")?, 32)
            && n(&w, "started_unix_seconds")? <= n(&w, "recorded_unix_seconds")?
            && n(&w, "recorded_unix_seconds")? <= clock
            && w["witness_set"] == contract["witness_set"]
            && w["witness_set_deployment_seal"] == contract["witness_set_deployment_seal"]
            && w["complete_DATA_bytes"] == DATA
            && w["raw_minimum_free_bytes"] == FLOOR
            && w["resource_credit_bytes"] == 0
            && w["DATA_ending_bytes"] == 0
            && w["guard_handoff_authorized"] == false
            && w["replay_admission_authorized"] == false
            && w["remote_mutations"] == false
            && w["producer_mutations"] == false,
        "actual same-image native witness qualification required",
    )?;
    need(
        w["source_provenance"]
            == json!({"complete_authority":seed["complete_authority"],"accepted_native70node_ancestry":seed["accepted_original154_ancestry"],"full_original_root_caps_preserved_bytes":7*CAP,"guard_metadata_preserved_bytes":7*(8u64<<30),"other_DATA_promises_preserved_bytes":DATA-7*(CAP+(8u64<<30)),"raw_minimum_free_bytes":FLOOR,"complete_DATA_bytes":DATA,"DATA_ending_bytes":0,"memory_credit_bytes":0}),
        "complete seven-role DATA provenance must remain exact",
    )?;
    let (_, total) = allocation(&w["allocation"])?;
    need(
        total >= maximum,
        "contract exceeds actual qualified allocation",
    )?;
    Ok(Accepted {
        protection: Value::Null,
        plan: contract,
        runtime,
        registration: r,
        native_witness: w,
        handoff: Value::Null,
    })
}
/// Validate a fresh actual sample without turning fulfilled bytes into a promise ending.
pub fn sample(a: &Accepted, g: &Value, c: &Context<'_>, clock: u64, current: bool) -> R<()> {
    let when = n(g, "recorded_unix_seconds")?;
    need(
        g["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && g["guard_sha256"] == a.runtime["sha256"]
            && g["plan_sha256"] == a.protection["plan"]["sha256"]
            && g["plan"] == a.protection["plan"]["path"]
            && g["producer_invocation_id"] == c.iid
            && g["producer"]["invocation_id"] == c.iid
            && g["producer"]["pid"] == c.pid
            && g["producer"]["restarts"] == 0
            && g["producer_stop_enabled"] == true
            && g.get("trip_reason") == Some(&Value::Null)
            && g.get("worker_observation_error") == Some(&Value::Null)
            && g.get("root_physical_observation_error") == Some(&Value::Null)
            && g.get("DATA_fulfillment_observation_error") == Some(&Value::Null)
            && g["scratch_deleted"] == false
            && g["minimum_free_bytes"] == FLOOR
            && g["maximum_root_physical_bytes"] == CAP
            && g["maximum_worker_vmas"] == 3_500_000
            && when >= c.start
            && when <= clock
            && g["remote_mutations"] == false
            && g["r2_mutations"] == false,
        "exact successor guard/sample/scope required",
    )?;
    need(
        !current || clock - when <= 45,
        "current successor guard sample stale",
    )?;
    let d = &g["DATA_fulfillment"];
    let contract = bound(&a.registration["contract"])?;
    let maximum = n(&contract, "maximum_fulfilled_bytes")?;
    need(
        d["schema"] == "horizon-original-slot-DATA-guard-observation-v1"
            && d["contract"] == a.plan["data_fulfillment"]
            && d["qualified_native_witness"] == contract["qualified_native_witness"]
            && d["source_provenance"] == a.native_witness["source_provenance"]
            && d["allocation"]["first"] == a.native_witness["allocation"]["first"]
            && d["raw_minimum_free_bytes"] == FLOOR
            && d["DATA_ending_bytes"] == 0
            && d["resource_credit_bytes"] == 0
            && d["remote_mutations"] == false
            && d["producer_mutations"] == false,
        "sample must bind revalidated qualified witness and unchanged promises",
    )?;
    let (measured, total) = allocation(&d["allocation"])?;
    let raw = n(d, "conservative_raw_available_bytes")?;
    let fulfilled = n(d, "fulfilled_bytes")?;
    let effective = FLOOR
        .checked_sub(fulfilled)
        .ok_or("fulfilled floor underflow")?;
    let sum = raw
        .checked_add(fulfilled)
        .ok_or("effective free overflow")?;
    need(
        total >= maximum
            && fulfilled == total.min(maximum)
            && raw == measured.min(n(d, "initial_raw_available_bytes")?)
            && raw == n(g, "available_bytes")?
            && n(g, "fulfilled_existing_DATA_bytes")? == fulfilled
            && n(g, "effective_required_free_bytes")? == effective
            && n(d, "effective_required_free_bytes")? == effective
            && n(g, "available_plus_fulfilled_bytes")? == sum
            && n(d, "available_plus_fulfilled_bytes")? == sum
            && sum >= FLOOR,
        "fresh no-trip raw-plus-fulfilled equation differs",
    )
}
pub fn proof(a: &Accepted, v: &Value, g: &Value, c: &Context<'_>) -> R<()> {
    completion(&a.protection, v, g, c)
}
fn completion(p: &Value, v: &Value, g: &Value, c: &Context<'_>) -> R<()> {
    let id = s(g, "guard_invocation_id")?;
    let service = &v["guard_service"];
    need(
        hex(id, 32)
            && service["Id"] == p["guard_unit"]
            && service["InvocationID"] == id
            && service["LoadState"] == "loaded"
            && service["ActiveState"] == "inactive"
            && service["SubState"] == "dead"
            && service["MainPID"] == "0"
            && service["ControlPID"] == "0"
            && service["NRestarts"] == "0"
            && service["Result"] == "success"
            && service["ExecMainStatus"] == "0"
            && service["Job"] == "",
        "actual successor guard completion required",
    )?;
    let rows = v["journal"].as_array().ok_or("actual PID1 journal")?;
    let matches =
        |r: &&Value| r["_PID"] == "1" && r["UNIT"] == p["guard_unit"] && r["INVOCATION_ID"] == id;
    need(
        rows.iter()
            .filter(matches)
            .any(|r| r["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448")
            && rows.iter().filter(matches).any(|r| {
                r["MESSAGE_ID"] == "39f53479d3a045ac8e11786248231fbf" && r["JOB_RESULT"] == "done"
            }),
        "genuine timer-driven PID1 guard lifecycle required",
    )?;
    timer(&v["timer"], p)?;
    owner(&v["actual_producer"], c)
}
pub fn load_handoff(binding: &Value, c: &Context<'_>, clock: u64) -> R<Accepted> {
    let expected_unit = format!(
        "horizon-qualify-{}-replacement-local2-20261110-v1.service",
        c.epoch
    );
    need(
        (166..=172).contains(&c.epoch) && c.unit == expected_unit && hex(c.iid, 32) && c.pid > 1,
        "exact current local2 context required",
    )?;
    let h = bound(binding)?;
    need(
        h["schema"] == "horizon-local2-DATA-guard-continuous-handoff-v1"
            && h["owner"] == "/root"
            && h["primary_thread"] == PRIMARY
            && h["epoch"] == c.epoch
            && h["original_protection"] == *c.original_protection
            && h["no_guard_gap"] == true
            && h["producer_restarts"] == 0
            && h["all_existing_files_and_prior_endings_retained"] == true
            && h["raw_minimum_free_bytes"] == FLOOR
            && h["complete_DATA_bytes"] == DATA
            && h["resource_credit_bytes"] == 0
            && h["DATA_ending_bytes"] == 0
            && h["memory_promise_ending_bytes"] == 0
            && h["replay_admission_authorized"] == false
            && h["remote_mutations"] == false
            && n(&h, "recorded_unix_seconds")? <= clock,
        "complete no-credit continuous handoff required",
    )?;
    let original = bound(c.original_protection)?;
    need(
        original["schema"] == "horizon-standard-live-peer-protection-v1"
            && original["owner"] == "/root"
            && original["epoch"] == c.epoch
            && original["producer_unit"] == c.unit
            && original["producer_invocation_id"] == c.iid
            && hex(s(&original, "timer_invocation_id")?, 32),
        "historical original protection must bind exact current producer",
    )?;
    let mut a = registration(&h["registration"], clock)?;
    let p = bound(&h["new_protection"])?;
    need(
        p["schema"] == "horizon-standard-live-peer-protection-v1"
            && p["owner"] == "/root"
            && p["epoch"] == c.epoch
            && p["producer_unit"] == c.unit
            && p["producer_invocation_id"] == c.iid
            && p["admission"] == original["admission"]
            && p["guard_runtime"] == a.runtime
            && p["DATA_guard_registration"] == h["registration"]
            && p["guard_unit"] != original["guard_unit"]
            && p["timer_unit"] != original["timer_unit"]
            && hex(s(&p, "timer_invocation_id")?, 32),
        "separate successor protection must retain actual original admission",
    )?;
    let plan = normal(
        &p["plan"],
        &p["plan_deployment_seal"],
        "guard-plan.json",
        "0444",
    )?;
    need(
        plan["schema"] == "jetstreamer-horizon-standalone-guard-plan-v1"
            && plan["unit"] == c.unit
            && plan["invocation_id"] == c.iid
            && plan["filesystem"] == "/home/sol"
            && plan["minimum_free_bytes"] == FLOOR
            && plan["maximum_root_physical_bytes"] == CAP
            && plan["maximum_worker_vmas"] == 3_500_000
            && plan["data_fulfillment"]
                == json!({"contract":a.registration["contract"],"deployment_seal":a.registration["contract_deployment_seal"]}),
        "successor plan must preserve raw floor/cap/VMA and exact optional contract",
    )?;
    let original_plan = bound(&original["plan"])?;
    need(
        plan["worker_root"] == original_plan["worker_root"]
            && plan["minimum_free_bytes"] == original_plan["minimum_free_bytes"]
            && plan["maximum_root_physical_bytes"] == original_plan["maximum_root_physical_bytes"]
            && plan["maximum_worker_vmas"] == original_plan["maximum_worker_vmas"],
        "historical protection limits must be preserved",
    )?;
    a.protection = p;
    a.plan = plan;
    a.handoff = h.clone();
    owner(&h["producer_before"], c)?;
    owner(&h["producer_after"], c)?;
    let completions = h["genuine_new_timer_completions"]
        .as_array()
        .ok_or("three actual guard completions")?;
    need(
        (3..=8).contains(&completions.len()),
        "bounded at least three genuine new timer completions required",
    )?;
    let mut seen = BTreeSet::new();
    let mut first = 0;
    let mut last = 0;
    for (i, b) in completions.iter().enumerate() {
        let v = bound(b)?;
        let g = bound(&v["receipt"])?;
        sample(&a, &g, c, clock, false)?;
        proof(&a, &v, &g, c)?;
        let when = n(&g, "recorded_unix_seconds")?;
        need(
            seen.insert(s(&g, "guard_invocation_id")?.to_owned()) && (i == 0 || when > last),
            "guard completion identity/clock repeated",
        )?;
        if i == 0 {
            first = when;
        }
        last = when;
        need(
            v["genuine_timer_driven_success"] == true,
            "completion cannot be manual-only guard invocation",
        )?;
        if i == 0 {
            need(
                v["receipt"] == a.protection["first_guard_sample"],
                "new first guard binding differs",
            )?;
        }
    }
    let span = last.checked_sub(first).ok_or("sustained handoff clock")?;
    need(
        (20..=120).contains(&span)
            && h["sustained_window_seconds"] == span
            && n(&h, "recorded_unix_seconds")? >= last
            && (h.get("interrupted_operator_recovery").is_some()
                || (n(&h, "old_guard_stop_started_unix_seconds")? >= last
                    && n(&h, "old_guard_stop_started_unix_seconds")?
                        <= n(&h, "recorded_unix_seconds")?)),
        "old guard must survive third genuine successor completion",
    )?;
    let old_proof = bound(&h["old_last_guard_pid1_timer"])?;
    let old_sample = bound(&old_proof["receipt"])?;
    let old_when = n(&old_sample, "recorded_unix_seconds")?;
    need(
        old_sample["schema"] == "jetstreamer-horizon-standalone-guard-sample-v1"
            && old_sample["guard_sha256"] == OLD
            && old_sample["plan_sha256"] == original["plan"]["sha256"]
            && old_sample["producer_invocation_id"] == c.iid
            && old_sample["producer"]["invocation_id"] == c.iid
            && old_sample["producer"]["pid"] == c.pid
            && old_sample["producer"]["restarts"] == 0
            && old_sample["producer_stop_enabled"] == true
            && old_sample.get("trip_reason") == Some(&Value::Null)
            && old_sample.get("worker_observation_error") == Some(&Value::Null)
            && old_sample.get("root_physical_observation_error") == Some(&Value::Null)
            && old_sample["scratch_deleted"] == false
            && old_sample["minimum_free_bytes"] == FLOOR
            && n(&old_sample, "available_bytes")? >= FLOOR
            && old_sample["maximum_root_physical_bytes"] == CAP
            && old_sample["maximum_worker_vmas"] == 3_500_000
            && old_when >= c.start
            && old_when <= last
            && first.saturating_sub(old_when) <= 45,
        "last original guard must genuinely protect same producer during overlap",
    )?;
    completion(&original, &old_proof, &old_sample, c)?;
    if h.get("interrupted_operator_recovery").is_some() {
        interrupted_recovery::validate(&a, &h, &original, c, last, clock)?;
    } else {
        timer(&h["old_timer_at_last_new_completion"], &original)?;
        need(
            n(&h, "old_timer_overlap_recorded_unix_seconds")? >= last
                && n(&h, "old_timer_overlap_recorded_unix_seconds")?
                    <= n(&h, "old_guard_stop_started_unix_seconds")?,
            "old timer overlap capture must precede its stop",
        )?;
        terminal(&h["old_timer_state"], &original["timer_unit"], false)?;
        terminal(&h["old_service_terminal"], &original["guard_unit"], true)?;
    }
    // Native readers additionally re-observe old terminal and new active units. These retained
    // receipts prove history and cannot silently replace any current native verification.
    Ok(a)
}

/// Re-observe drained original scopes only after full load_handoff acceptance.
/// The ordinary path remains strict; only the exact pinned166 recovery preserves its
/// genuinely SIGTERM-failed but empty original service.
pub fn current_old_terminal(a: &Accepted, v: &Value, unit: &Value, service: bool) -> R<()> {
    if a.handoff.get("interrupted_operator_recovery").is_some() {
        need(
            a.handoff["epoch"] == 166,
            "recovery terminal must retain exact166",
        )?;
        if service {
            let r = bound(&a.handoff["interrupted_operator_recovery"])?;
            need(
                v["InvocationID"] == r["old_service_terminal"]["InvocationID"],
                "failed original service IID changed after recovery",
            )?;
        }
        interrupted_recovery::terminal166(v, unit, service)
    } else {
        terminal(v, unit, service)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn witness() -> Value {
        let mut rows = Vec::new();
        let mut per = serde_json::Map::new();
        for e in 166..=170 {
            for i in 0..3 {
                rows.push(json!({"epoch":e,"path":format!("/home/sol/.jetstreamer-private/epoch{e}-standard-lane-20261109-v1/closed/member{i}"),"dev":7,"ino":e*10+i,"uid":1001,"gid":1003,"mode":0o100600,"nlink":1,"logical_bytes":2u64<<30,"allocated_blocks512":(2u64<<30)/512,"mtime":1,"mtime_nsec":0,"ctime":1,"ctime_nsec":0,"birth_seconds":1,"birth_nanoseconds":0,"ancestors":[{"path":"/","ino":2}]}));
            }
            per.insert(e.to_string(), json!(5u64 << 30));
        }
        let free = json!({"device":7,"filesystem_magic":0xef53,"available_bytes":FLOOR-100});
        json!({"first":rows,"second":rows,"filesystem_before":free,"filesystem_midpoint":free,"filesystem_after":free,"conservative_available_bytes":FLOOR-100,"per_slot":per,"conservative_fulfilled_bytes":25u64<<30})
    }
    #[test]
    fn allocation_reader_recomputes_blocks_and_all_five_slot_margins() {
        assert_eq!(allocation(&witness()).unwrap(), (FLOOR - 100, 25u64 << 30));
        let mut sparse = witness();
        for k in ["first", "second"] {
            for f in sparse[k].as_array_mut().unwrap() {
                f["logical_bytes"] = json!(u64::MAX);
            }
        }
        assert_eq!(allocation(&sparse).unwrap().1, 25u64 << 30);
    }
    #[test]
    fn foreign_device_hardlink_inode_alias_and_duplicate_path_fail() {
        for k in ["dev", "nlink", "ino", "path"] {
            let mut a = witness();
            let v = match k {
                "dev" => json!(8),
                "nlink" => json!(2),
                _ => a["first"][1][k].clone(),
            };
            a["first"][0][k] = v.clone();
            a["second"][0][k] = v;
            assert!(allocation(&a).is_err(), "{k}");
        }
    }
    #[test]
    fn unknown_shared_filesystem_or_changed_midpoint_counters_fail() {
        for (key, value) in [
            ("device", json!(8)),
            ("filesystem_magic", json!(0x9123683eu64)),
        ] {
            let mut a = witness();
            a["filesystem_midpoint"][key] = value;
            assert!(allocation(&a).is_err());
        }
        let mut a = witness();
        a["filesystem_before"]["available_bytes"] = json!(1);
        assert!(allocation(&a).is_err());
    }
    #[test]
    fn missing_slot_replacement_changed_endpoints_and_nonregular_files_fail() {
        for k in ["first", "second"] {
            let mut a = witness();
            a[k][0]["ino"] = json!(8000);
            assert!(allocation(&a).is_err());
        }
        for (key, value) in [
            ("epoch", json!(171)),
            ("mode", json!(0o120600)),
            ("uid", json!(0)),
            ("birth_seconds", json!(0)),
            ("birth_nanoseconds", json!(1_000_000_000)),
            (
                "path",
                json!("/home/sol/.jetstreamer-private/elsewhere/member"),
            ),
        ] {
            let mut a = witness();
            a["first"][0][key] = value.clone();
            a["second"][0][key] = value;
            assert!(allocation(&a).is_err(), "{key}");
        }
        let mut a = witness();
        a["first"].as_array_mut().unwrap().pop();
        a["second"].as_array_mut().unwrap().pop();
        assert!(allocation(&a).is_err());
    }
    #[test]
    fn false_allocation_total_margin_cap_and_overflow_cannot_buy_capacity() {
        for value in [u64::MAX, CAP / 512 + 1] {
            let mut a = witness();
            for k in ["first", "second"] {
                a[k][0]["allocated_blocks512"] = json!(value);
            }
            assert!(allocation(&a).is_err());
        }
        for key in [
            "conservative_fulfilled_bytes",
            "conservative_available_bytes",
        ] {
            let mut a = witness();
            a[key] = json!(u64::MAX);
            assert!(allocation(&a).is_err());
        }
        let mut a = witness();
        a["per_slot"]["166"] = json!(6u64 << 30);
        assert!(allocation(&a).is_err());
    }
    fn completed() -> (Value, Value, Value, Value) {
        let p = json!({"guard_unit":"new-guard.service","timer_unit":"new-guard.timer","timer_invocation_id":"b".repeat(32)});
        let g = json!({"guard_invocation_id":"c".repeat(32)});
        let owner = json!({"Id":"horizon-qualify-166-replacement-local2-20261110-v1.service","InvocationID":"a".repeat(32),"MainPID":"123","ControlPID":"0","NRestarts":"0","ActiveState":"active","SubState":"running","Job":""});
        let timer = json!({"Id":"new-guard.timer","InvocationID":"b".repeat(32),"LoadState":"loaded","ActiveState":"active","SubState":"waiting","Triggers":"new-guard.service","Job":""});
        let service = json!({"Id":"new-guard.service","InvocationID":"c".repeat(32),"LoadState":"loaded","ActiveState":"inactive","SubState":"dead","MainPID":"0","ControlPID":"0","NRestarts":"0","Result":"success","ExecMainStatus":"0","Job":""});
        let journal = json!([{"_PID":"1","UNIT":"new-guard.service","INVOCATION_ID":"c".repeat(32),"MESSAGE_ID":"7ad2d189f7e94e70a38c781354912448"},{"_PID":"1","UNIT":"new-guard.service","INVOCATION_ID":"c".repeat(32),"MESSAGE_ID":"39f53479d3a045ac8e11786248231fbf","JOB_RESULT":"done"}]);
        (
            p,
            g,
            json!({"guard_service":service,"actual_producer":owner,"timer":timer,"journal":journal}),
            json!({"path":"/sealed/original.json","sha256":"d".repeat(64)}),
        )
    }
    #[test]
    fn completion_requires_both_actual_pid1_events_and_same_owner_and_timer() {
        let (p, g, v, original) = completed();
        let iid = "a".repeat(32);
        let c = Context {
            epoch: 166,
            unit: "horizon-qualify-166-replacement-local2-20261110-v1.service",
            iid: &iid,
            pid: 123,
            start: 1,
            original_protection: &original,
        };
        completion(&p, &v, &g, &c).unwrap();
        for pointer in [
            "/guard_service/InvocationID",
            "/timer/InvocationID",
            "/actual_producer/InvocationID",
            "/journal/1/INVOCATION_ID",
        ] {
            let mut changed = v.clone();
            *changed.pointer_mut(pointer).unwrap() = json!("e".repeat(32));
            assert!(completion(&p, &changed, &g, &c).is_err(), "{pointer}");
        }
        for pointer in [
            "/guard_service/Result",
            "/timer/ActiveState",
            "/actual_producer/NRestarts",
            "/journal/0/_PID",
            "/journal/1/JOB_RESULT",
        ] {
            let mut changed = v.clone();
            *changed.pointer_mut(pointer).unwrap() = json!("bad");
            assert!(completion(&p, &changed, &g, &c).is_err(), "{pointer}");
        }
    }
    #[test]
    fn legacy_terminal_shape_cannot_claim_a_running_new_timer() {
        let old = json!("old-guard.service");
        let v = json!({"Id":old,"LoadState":"loaded","ActiveState":"inactive","SubState":"dead","Job":"","MainPID":"0","ControlPID":"0","NRestarts":"0","ControlGroup":""});
        terminal(&v, &old, true).unwrap();
        for key in ["ActiveState", "MainPID", "ControlGroup"] {
            let mut changed = v.clone();
            changed[key] = json!("1");
            assert!(terminal(&changed, &old, true).is_err());
        }
    }
    #[test]
    fn unknown_images_and_changed_registration_envelopes_are_rejected() {
        let entry = json!({"path":"/sealed/registration.json","sha256":"a".repeat(64),"deployment_seal":{"path":"/sealed/deployment-seal-receipt.json","sha256":"b".repeat(64)}});
        registered_binding(&entry, &json!([entry])).unwrap();
        assert!(registered_binding(&entry, &json!([])).is_err());
        assert!(registered_binding(&entry, &json!([entry, entry])).is_err());
        for pointer in ["/sha256", "/path", "/deployment_seal/sha256"] {
            let mut changed = entry.clone();
            *changed.pointer_mut(pointer).unwrap() = json!("changed");
            assert!(registered_binding(&changed, &json!([entry])).is_err());
        }
    }
}
