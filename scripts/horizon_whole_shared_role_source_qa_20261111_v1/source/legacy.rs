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
pub(super) type R<T> = Result<T, Box<dyn std::error::Error>>;
const IMAGE: &str =
    "/usr/local/lib/jetstreamer/horizon-shared64-owner-census-tools-20261110-v3/check";
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
pub(super) fn raw(path: &Path) -> R<Vec<u8>> {
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
pub(super) fn bound(b: &Value) -> R<Value> {
    let bytes = raw(Path::new(s(b, "path")?))?;
    need(
        sha(&bytes) == s(b, "sha256")?,
        "bound metadata digest mismatch",
    )?;
    Ok(serde_json::from_slice(&bytes)?)
}
pub(super) fn durable(path: &Path, value: &Value) -> R<()> {
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
pub(super) fn native(name: &str) -> R<Value> {
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
fn discover() -> R<BTreeSet<String>> {
    let text = command(
        &[
            "list-units",
            "--all",
            "--plain",
            "--no-legend",
            "--no-pager",
            "--type=service",
            "--type=timer",
        ],
        16 << 20,
    )?;
    let mut out = BTreeSet::new();
    for line in text.lines() {
        let name = line
            .split_whitespace()
            .next()
            .ok_or("empty loaded unit row")?;
        if name.contains("horizon") || name.contains("epoch") || name.contains("root-sweep") {
            unit_name(name)?;
            need(out.insert(name.into()), "duplicate loaded unit")?;
        }
    }
    Ok(out)
}
fn live(v: &Value) -> bool {
    v["ActiveState"] == "active"
        && v["SubState"] == "running"
        && v["MainPID"]
            .as_str()
            .is_some_and(|x| x.parse::<u64>().is_ok_and(|p| p > 0))
}
pub(super) fn owner_matches(actual: &Value, expected: &Value) -> R<()> {
    need(
        live(actual) && actual["NRestarts"] == "0" && actual["ControlPID"] == "0",
        "owner not stable running",
    )?;
    for (native_key, plan_key) in [
        ("Id", "unit"),
        ("InvocationID", "invocation_id"),
        ("MainPID", "main_pid"),
    ] {
        need(
            actual[native_key] == expected[plan_key],
            "owner identity mismatch",
        )?;
    }
    Ok(())
}
pub(super) fn fixed_verification_cap(unit: &str) -> R<u64> {
    if unit == "jetstreamer-horizon-plugin-receipt-watcher-shard-c-v4-fsync.service" {
        return Ok(32 << 30);
    }
    if unit == "jetstreamer-horizon-audit-epochs101-181-v4.service" {
        return Ok(32 << 30);
    }
    if unit == "jetstreamer-horizon-boundary-audit-101-181-v6-fsync.service"
        || ["a", "b", "c", "d"].iter().any(|part| {
            unit == format!(
                "jetstreamer-horizon-plugin-receipt-watcher-shard-{part}-v4-fsync.service"
            )
        })
    {
        return Ok(8 << 30);
    }
    Err("unknown verification pool role".into())
}
pub(super) fn verification_native(rows: &[Value]) -> R<Value> {
    let mut result = Vec::new();
    for row in rows {
        let name = s(row, "unit")?;
        let cap = fixed_verification_cap(name)?;
        let value = native(name)?;
        if value["LoadState"] == "not-found" {
            need(
                name == "jetstreamer-horizon-plugin-receipt-watcher-shard-a-v4-fsync.service"
                    && value["ActiveState"] == "inactive"
                    && value["SubState"] == "dead"
                    && value["MainPID"] == "0"
                    && value["ControlPID"] == "0"
                    && value["Job"] == "",
                "only exact collected shardA may retain its conservative8GiB future slot",
            )?;
        } else {
            need(
                value["MemoryMax"]
                    .as_str()
                    .and_then(|v| v.parse::<u64>().ok())
                    == Some(cap)
                    && value["MemorySwapMax"] == "0"
                    && value["Delegate"] == "no"
                    && value["KillMode"] == "control-group",
                "actual bounded descendant verification envelope differs",
            )?;
        }
        let binding = &row["immutable_script"];
        let bytes = raw(Path::new(s(binding, "path")?))?;
        need(
            sha(&bytes) == s(binding, "sha256")?,
            "verification script bytes changed",
        )?;
        let script = String::from_utf8(bytes)?;
        need(
            !script.contains("systemd-run")
                && !script.contains("systemctl")
                && !script.contains("setsid")
                && !script.contains("nohup"),
            "unqualified verifier cgroup escape route",
        )?;
        result.push(json!({"unit":name,"retained_cap_bytes":cap,"native":value,"immutable_script":binding,"slot_retained_even_when_collected":true}));
    }
    Ok(json!(result))
}
fn executing(v: &Value) -> bool {
    v["MainPID"]
        .as_str()
        .is_some_and(|s| s.parse::<u64>().is_ok_and(|x| x > 0))
        || v["ControlPID"]
            .as_str()
            .is_some_and(|s| s.parse::<u64>().is_ok_and(|x| x > 0))
}
const PROTECTED_BACKGROUND_UNITS: [&str; 7] = [
    "horizon-r2-progressive-epochs101-200-v21-rust-authenticated.service",
    "jetstreamer-epoch199-backfill-20261102-controller-v1-r2.service",
    "jetstreamer-horizon-audit-epochs101-181-v4.service",
    "jetstreamer-horizon-boundary-audit-101-181-v6-fsync.service",
    "jetstreamer-horizon-plugin-receipt-watcher-shard-b-v4-fsync.service",
    "jetstreamer-horizon-plugin-receipt-watcher-shard-c-v4-fsync.service",
    "jetstreamer-horizon-plugin-receipt-watcher-shard-d-v4-fsync.service",
];
pub(super) fn complete_background_census(rows: &[Value]) -> R<()> {
    // The two stable controllers are only a subset of the protected fleet.
    // Retain the five running verifier owners too; shard A's future slot stays
    // charged separately by verification_fit and verification_native.
    let expected = PROTECTED_BACKGROUND_UNITS
        .into_iter()
        .collect::<BTreeSet<_>>();
    let mut actual = BTreeSet::new();
    for row in rows {
        let unit = s(row, "unit")?;
        unit_name(unit)?;
        need(actual.insert(unit), "duplicate protected background owner")?;
    }
    let missing = expected.difference(&actual).copied().collect::<Vec<_>>();
    let extra = actual.difference(&expected).copied().collect::<Vec<_>>();
    need(
        missing.is_empty() && extra.is_empty(),
        &format!("protected background census differs; missing={missing:?}; extra={extra:?}"),
    )
}
fn classify(
    unit: &str,
    value: &Value,
    owners: &BTreeMap<String, Value>,
    guards: &BTreeMap<String, Value>,
    own: &str,
) -> R<()> {
    let job = value["Job"].as_str().ok_or("native job property missing")?;
    if let Some(expected) = owners.get(unit) {
        owner_matches(value, expected)?;
        return Ok(());
    }
    if let Some(expected) = guards.get(unit) {
        need(
            value["MemoryMax"] == expected["MemoryMax"]
                && value["MemorySwapMax"] == "0"
                && value["Restart"] == "no",
            "separate guard hard envelope changed",
        )?;
        return Ok(());
    }
    if unit == own {
        need(
            live(value)
                && value["MemoryMax"] == "536870912"
                && value["MemorySwapMax"] == "0"
                && value["NRestarts"] == "0",
            "native check must use existing Root callback512",
        )?;
        return Ok(());
    }
    need(
        !executing(value) && job.is_empty(),
        &format!(
            "unclassified executing or queued Horizon unit {unit}; no native-pool reuse authority; native={value}"
        ),
    )
}

pub(super) fn retained_caps(rows:&[Value])->R<u64>{need(rows.len()==6,"six future/actual verification roles required")?;let mut names=BTreeSet::new();let mut sum=0u64;for row in rows{let name=s(row,"unit")?;need(names.insert(name),"duplicate verification role")?;let cap=fixed_verification_cap(name)?;need(n(row,"retained_cap_bytes")?==cap,"retained verification cap changed")?;sum=sum.checked_add(cap).ok_or("cap sum overflow")?;}need(sum==96u64<<30,"all96GiB verification caps retained")?;Ok(sum)}
fn capture(owners:&BTreeMap<String,Value>,guards:&BTreeMap<String,Value>,own:&str)->R<(BTreeMap<String,Value>,Value)>{let mut names=discover()?;names.extend(owners.keys().cloned());names.extend(guards.keys().cloned());names.insert(own.into());let mut all=BTreeMap::new();let mut unresolved=Vec::new();for name in &names{let v=native(name)?;if let Err(e)=classify(name,&v,owners,guards,own){unresolved.push(json!({"unit":name,"native":v,"reason":e.to_string()}));}all.insert(name.clone(),v);}need(discover()?.is_subset(&names),"new loaded Horizon unit appeared during census")?;Ok((all,json!(unresolved)))}
fn active_summary(all:&BTreeMap<String,Value>)->Value{json!(all.iter().filter(|(_,v)|executing(v)||v["Job"]!="").map(|(k,v)|json!({"unit":k,"native":v})).collect::<Vec<_>>())}
fn run()->R<()> {
 let args=std::env::args().collect::<Vec<_>>();need(args.len()==6 && args[2]=="--plan-sha256" && args[4]=="--self-sha256","plan/digest/self arguments required")?;
 need(fs::read_link("/proc/self/exe")?==Path::new(IMAGE) && sha(&raw(Path::new(IMAGE))?)==args[5],"normal sealed exact image required")?;
 let plan=bound(&json!({"path":args[1],"sha256":args[3]}))?;need(plan["schema"]=="horizon-shared64-owner-census-plan-v1" && plan["owner"]=="/root" && plan["primary_thread"]=="01a1af2a-9ce8-76a2-8939-b2112bd38f53","exclusive Root plan required")?;
 let head=bound(&plan["current_complete_authority"])?;let fleet=bound(&plan["current_fleet"])?;let original=bound(&plan["original_pool_facts"])?;
 need(head["complete_projected_memory_bytes"]==708_249_923_584u64 && head["complete_DATA_bytes"]==6_101_056_700_210u64 && head["normal_pool_bytes"]==10u64<<30 && original["existing_pools_bytes"]["shared64GiB"]==64u64<<30 && original["existing_pools_bytes"]["compiler_and_native16GiB"]==16u64<<30,"full current authority/shared64/native16 unchanged")?;
 need(fleet["schema"]=="horizon-Root-complete-fleet-operational-review-v1" && fleet["complete_DATA_authority"]==plan["current_complete_authority"] && fleet["live_replay_count"]==7 && fleet["proven_replay_count"]==7 && fleet["authenticated_status_count"]==19,"complete seven-owner fleet required")?;
 need(plan["retained_native_pool_bytes"]==16u64<<30 && plan["native_committed_before_bytes"]==13_757_317_120u64 && plan["one_serial_native_callback_bytes"]==512u64<<20 && n(&plan,"native_committed_before_bytes")?.checked_add(n(&plan,"one_serial_native_callback_bytes")?).is_some_and(|x|x<=16u64<<30),"funded serial native16 callback required")?;
 let own="horizon-shared64-owner-census-current-20261110-v3.service";let me=native(own)?;need(live(&me) && s(&me,"MainPID")?.parse::<u32>()?==std::process::id() && me["InvocationID"]==std::env::var("INVOCATION_ID")? && me["MemoryMax"]=="536870912" && me["MemorySwapMax"]=="0" && me["Restart"]=="no" && me["NRestarts"]=="0","exact funded own native identity required")?;
 let mut owners=BTreeMap::new();let rows=fleet["actual_executing_replays"].as_array().ok_or("complete seven actual replays")?;need(rows.len()==7,"seven replay owners required")?;
 for row in rows{let unit=&row["unit"];let name=s(unit,"Id")?;let expected=json!({"unit":name,"invocation_id":unit["InvocationID"],"main_pid":unit["MainPID"]});need(owners.insert(name.to_string(),expected).is_none(),"duplicate replay owner")?;}
 let backgrounds=plan["protected_background_owners"].as_array().ok_or("all protected background owners")?;complete_background_census(backgrounds)?;for row in backgrounds{need(owners.insert(s(row,"unit")?.into(),row.clone()).is_none(),"overlapping protected owner")?;}
 let mut before_owners=BTreeMap::new();for(name,expected)in &owners{let v=native(name)?;owner_matches(&v,expected)?;before_owners.insert(name.clone(),v);}
 let guard_rows=plan["normal_guard_roles"].as_array().ok_or("seven normal guards")?;need(guard_rows.len()==7,"seven separately-funded guards required")?;let mut guards=BTreeMap::new();for row in guard_rows{need(row["MemoryMax"]=="1073741824" && guards.insert(s(row,"unit")?.into(),row.clone()).is_none(),"guard envelope duplicate/changed")?;}
 let verifiers=plan["retained_verification_roles"].as_array().ok_or("all verification roles")?;let caps=retained_caps(verifiers)?;let vb=verification_native(verifiers)?;
 let (before,unknown_before)=capture(&owners,&guards,own)?;let (after,unknown_after)=capture(&owners,&guards,own)?;let va=verification_native(verifiers)?;
 for(name,v)in &before_owners{need(native(name)?==*v,"protected owner/cap changed during native census")?;}need(native(own)?==me,"own native changed during census")?;
 for key in["current_complete_authority","current_fleet","original_pool_facts"]{bound(&plan[key])?;}
 let report=json!({"schema":"horizon-shared64-owner-census-report-v1","owner":"/root","primary_thread":plan["primary_thread"],"recorded_unix_seconds":now()?,"plan":plan,"native_before_count":before.len(),"native_after_count":after.len(),"native_before_sha256":sha(&serde_json::to_vec(&before)?),"native_after_sha256":sha(&serde_json::to_vec(&after)?),"active_or_queued_before":active_summary(&before),"active_or_queued_after":active_summary(&after),"unclassified_before":unknown_before,"unclassified_after":unknown_after,"protected_owners_before":before_owners,"verification_before":vb,"verification_after":va,"all96_actual_and_future_verifier_caps_retained_bytes":caps,"retained_native16_bytes":16u64<<30,"retained_raw_shared_pool_bytes":64u64<<30,"actual_and_future_host_system_kernel_shared_obligations_not_yet_qualified":true,"shared_budget_ending_authorized":false,"new_replay_admission_authorized":false,"new_resource_observations":false,"new_physical_or_DATA_credit_bytes":0,"new_memory_credit_bytes":0,"producer_or_guard_mutations":false,"remote_mutations":false,"next_gate":"Bind every actual/future shared host/system/kernel and uncapped-controller allocation before proposing a lower future reserve. Metadata owner coverage alone is insufficient; no lower shared envelope is selected."});durable(Path::new(s(&plan,"output")?),&report)?;println!("{}",json!({"output":plan["output"],"native_before_count":before.len(),"native_after_count":after.len(),"unknown_before":report["unclassified_before"].as_array().ok_or("unknown list")?.len(),"unknown_after":report["unclassified_after"].as_array().ok_or("unknown list")?.len(),"memory_credit_bytes":0,"shared_budget_ending_authorized":false}));Ok(())
}
fn main(){if let Err(e)=run(){eprintln!("{e}");std::process::exit(1);}}
#[cfg(test)]mod tests{use super::*;
 fn roles()->Vec<Value>{["jetstreamer-horizon-audit-epochs101-181-v4.service","jetstreamer-horizon-boundary-audit-101-181-v6-fsync.service","jetstreamer-horizon-plugin-receipt-watcher-shard-a-v4-fsync.service","jetstreamer-horizon-plugin-receipt-watcher-shard-b-v4-fsync.service","jetstreamer-horizon-plugin-receipt-watcher-shard-c-v4-fsync.service","jetstreamer-horizon-plugin-receipt-watcher-shard-d-v4-fsync.service"].into_iter().map(|u|json!({"unit":u,"retained_cap_bytes":fixed_verification_cap(u).unwrap()})).collect()}
 #[test]fn future_verification_slots_count_exactly96_even_when_no_worker(){assert_eq!(retained_caps(&roles()).unwrap(),96u64<<30);let mut r=roles();r[4]["retained_cap_bytes"]=json!(8u64<<30);assert!(retained_caps(&r).is_err());}
 #[test]fn missing_duplicate_and_unknown_future_roles_fail(){let r=roles();assert!(retained_caps(&r[..5]).is_err());let mut d=r.clone();d[5]=d[4].clone();assert!(retained_caps(&d).is_err());let mut d=r;d[5]["unit"]=json!("unknown.service");assert!(retained_caps(&d).is_err());}
 #[test]fn full_protected_background_includes_five_verifiers(){let r=PROTECTED_BACKGROUND_UNITS.map(|u|json!({"unit":u}));assert!(complete_background_census(&r).is_ok());assert!(complete_background_census(&r[..2]).is_err());}
 #[test]fn unknown_executing_or_queued_owner_is_unclassified(){for v in[json!({"MainPID":"1","ControlPID":"0","Job":""}),json!({"MainPID":"0","ControlPID":"0","Job":"1"})]{assert!(classify("unknown.service",&v,&BTreeMap::new(),&BTreeMap::new(),"own.service").is_err());}}
 #[test]fn terminal_unknown_is_metadata_not_future_credit(){assert!(classify("old.service",&json!({"MainPID":"0","ControlPID":"0","Job":""}),&BTreeMap::new(),&BTreeMap::new(),"own.service").is_ok());}
 #[test]fn exact_active_owner_identity_is_required(){let expected=json!({"unit":"x.service","invocation_id":"iid","main_pid":"5"});let mut actual=json!({"Id":"x.service","InvocationID":"iid","MainPID":"5","ControlPID":"0","NRestarts":"0","ActiveState":"active","SubState":"running"});assert!(owner_matches(&actual,&expected).is_ok());actual["NRestarts"]=json!("1");assert!(owner_matches(&actual,&expected).is_err());}
 #[test]fn guard_caps_cannot_change(){let guards=BTreeMap::from([("g.service".into(),json!({"MemoryMax":"1073741824"}))]);let mut v=json!({"MemoryMax":"1073741824","MemorySwapMax":"0","Restart":"no","Job":""});assert!(classify("g.service",&v,&BTreeMap::new(),&guards,"own.service").is_ok());v["MemoryMax"]=json!("536870912");assert!(classify("g.service",&v,&BTreeMap::new(),&guards,"own.service").is_err());}
 #[test]fn unit_names_reject_switches_and_nonunits(){assert!(unit_name("x.service").is_ok());assert!(unit_name("--help").is_err());assert!(unit_name("x.target").is_err());}
}
