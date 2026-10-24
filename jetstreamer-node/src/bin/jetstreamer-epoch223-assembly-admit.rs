//! Authenticate the actual future handoff plus independent fresh capacity.
//! Source-only preparation: no replay, archive scan, launch, publication or R2.
#![recursion_limit = "256"]
#[allow(dead_code)]
#[path = "../../../jetstreamer-utils/src/epoch141_ledger_common.rs"]
mod evidence;
#[allow(dead_code)]
#[path = "epoch223_assembly/handoff.rs"]
mod handoff;
use anyhow::{Context, Result, ensure};
use handoff::Bound;
use jetstreamer_horizon_observe::source_idle223::{self, Source};
use jetstreamer_node::segment_manifest::sha256_hex_string;
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    env,
    fs::{self, File},
    io::Write,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
const OUTPUT: &str = "/var/lib/jetstreamer/horizon-223-native20-native25-private-assembly-v1";
const GATE_SHA: &str = "137b5a3a767604ea4c9f7405dd0af7af0eb860f30e5ece52ce49017825d35c22";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    handoff_request: Bound,
    handoff_receipt: Bound,
    capacity: Bound,
    capacity_tool_sha256: String,
    assembler_sha256: String,
    output: PathBuf,
}
fn read(b: &Bound) -> Result<Value> {
    Ok(serde_json::from_slice(&evidence::bound_file(
        &b.path,
        &b.sha256,
        8 << 20,
        true,
    )?)?)
}
fn seconds() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn capacity(c: &Value, tool: &str, now: u64) -> Result<(u64, u64)> {
    ensure!(
        evidence::is_sha(tool)
            && c["schema"] == "jetstreamer-private223-assembly-capacity-v1"
            && c["self_sha256"] == tool
            && c["assembly_only_no_replay"] == true
            && c["all_live_growth_and_century_floor_protected"] == true
            && c["first_epoch"] == 201
            && c["last_epoch"] == 300
            && c["new_resource_samples"] == 0
            && c["additional_bytes"] == ((160u64 << 30) + (32 << 20))
            && c["recorded_unix_seconds"]
                .as_u64()
                .is_some_and(|t| t <= now && now - t <= 900),
        "private 223 capacity identity/scope/freshness differs"
    );
    for key in [
        "replay_launch_authorized",
        "local_retirement_authorized",
        "publication_authorized",
        "r2_mutations",
        "assembly_launch_authorized",
        "source_completion_authenticated",
    ] {
        ensure!(
            c[key] == false,
            "capacity claimed unexpected authority:{key}"
        );
    }
    let floor = c["minimum_free_bytes"]
        .as_u64()
        .filter(|n| *n >= 2_000_000_000_000)
        .context("private 223 protected disk floor")?;
    let required = floor
        .checked_add((160 << 30) + (32 << 20))
        .context("private 223 capacity disk overflow")?;
    ensure!(
        c["required_initial_free_bytes"] == required
            && c["sampled_available_bytes"]
                .as_u64()
                .is_some_and(|n| n >= required)
            && c["actual_available_bytes"]
                .as_u64()
                .is_some_and(|n| n >= required),
        "private 223 capacity disk does not fit"
    );
    let mut required_memory = 0;
    for key in ["memory_before", "memory_after"] {
        let m = &c[key];
        let total = m["host_total_memory_bytes"]
            .as_u64()
            .filter(|n| *n > 0)
            .context("private 223 total memory")?;
        let growth = m["protected_existing_memory_growth_bytes"]
            .as_u64()
            .context("private 223 protected memory growth")?;
        let required = total
            .div_ceil(10)
            .checked_add(growth)
            .and_then(|n| n.checked_add(64 << 30))
            .context("private 223 memory overflow")?;
        ensure!(
            m["candidate_memory_max_bytes"] == (64u64 << 30)
                && m["memory_target_percent"] == 90
                && m["minimum_available_memory_bytes"] == required
                && m["sampled_available_memory_bytes"]
                    .as_u64()
                    .is_some_and(|n| n >= required)
                && m["actual_available_memory_bytes"]
                    .as_u64()
                    .is_some_and(|n| n >= required),
            "private 223 candidate memory does not fit"
        );
        required_memory = required_memory.max(required);
    }
    Ok((floor, required_memory))
}
fn scope(p: &Plan) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-private223-assembly-admission-request-v1"
            && evidence::is_sha(&p.assembler_sha256)
            && evidence::is_sha(&p.capacity_tool_sha256)
            && p.output.parent().and_then(Path::parent) == Some(Path::new("/var/lib/jetstreamer"))
            && p.output
                .parent()
                .and_then(Path::file_name)
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-223-assembly-admission-"))
            && p.output.file_name().is_some_and(|n| n == "admission.json"),
        "private 223 admission request/output differs"
    );
    Ok(())
}
fn run() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "private 223 admission requires root"
    );
    let args: Vec<_> = env::args().skip(1).collect();
    ensure!(args.len() == 3, "usage: PLAN PLAN_SHA256 SELF_SHA256");
    evidence::bound_file(&fs::read_link("/proc/self/exe")?, &args[2], 128 << 20, true)?;
    let plan_binding = Bound {
        path: args[0].clone().into(),
        sha256: args[1].clone(),
    };
    let p: Plan = serde_json::from_value(read(&plan_binding)?)?;
    scope(&p)?;
    let request: handoff::Plan = serde_json::from_value(read(&p.handoff_request)?)?;
    let prepared = handoff::prepare(&request)?;
    let actual = read(&p.handoff_receipt)?;
    ensure!(
        actual["self_sha256"] == GATE_SHA
            && actual["plan"]["path"].as_str() == p.handoff_request.path.to_str()
            && actual["plan"]["sha256"] == p.handoff_request.sha256,
        "not the actual qualified handoff gate"
    );
    for (key, value) in prepared
        .receipt
        .as_object()
        .context("handoff receipt object")?
    {
        ensure!(
            actual.get(key) == Some(value),
            "actual handoff evidence differs:{key}"
        );
    }
    let c = read(&p.capacity)?;
    let (floor, minimum_memory) = capacity(&c, &p.capacity_tool_sha256, seconds()?)?;
    for key in ["fleet", "observer"] {
        let b: Bound = serde_json::from_value(c[key].clone())?;
        read(&b)?;
    }
    let idle = json!({"prefix":source_idle223::observe(Source::Prefix)?,"tail":source_idle223::observe(Source::Tail)?});
    // Freshness and all metadata identities must survive the complete idle census.
    ensure!(
        read(&p.capacity)? == c && read(&p.handoff_receipt)? == actual,
        "private 223 evidence changed during admission"
    );
    capacity(&c, &p.capacity_tool_sha256, seconds()?)?;
    let parent = p.output.parent().context("private 223 admission parent")?;
    let m = fs::symlink_metadata(parent)?;
    ensure!(
        parent.canonicalize()? == parent && m.is_dir() && m.uid() == 0 && m.mode() & 0o777 == 0o700,
        "private 223 admission output must be canonical root-private"
    );
    let output_meta = fs::symlink_metadata(OUTPUT)?;
    ensure!(
        output_meta.is_dir()
            && output_meta.uid() == 0
            && output_meta.mode() & 0o077 == 0
            && Path::new(OUTPUT).canonicalize()? == Path::new(OUTPUT),
        "private 223 assembly output root differs"
    );
    let mut receipt = json!({"schema":"jetstreamer-private223-v3-assembly-admission-v1","admitted":true,"assembly_only_no_replay":true,
        "request":plan_binding,"self_sha256":args[2],"capacity":p.capacity,"assembler_sha256":p.assembler_sha256,
        "handoff_request_sha256":p.handoff_request.sha256,"handoff_receipt_sha256":p.handoff_receipt.sha256,
        "prefix_archive_sha256":sha256_hex_string(&prepared.prefix.archive_sha256),"tail_archive_sha256":sha256_hex_string(&prepared.tail.archive_sha256),
        "output_root":OUTPUT,"output_filesystem_device":output_meta.dev(),"maximum_archive_bytes":160u64<<30,
        "candidate_memory_max_bytes":64u64<<30,"candidate_memory_high_bytes":48u64<<30,"maximum_runtime_seconds":86400,
        "recorded_unix_seconds":seconds()?,"fleet_ledger":c["fleet"],"observer_receipt":c["observer"],
        "protected_existing_floor_bytes":floor,"required_guard_minimum_free_bytes":floor,"available_bytes":c["actual_available_bytes"],
        "protected_existing_memory_reserve_bytes":minimum_memory-(64u64<<30),"minimum_available_memory_bytes":minimum_memory,
        "complete_fleet_census_passed":true,"older_producer_guards_preserved":true,"current_century_floor_preserved":true,
        "fresh_invocation_bound_resource_sample":true,"source_idle":idle});
    for key in [
        "replay_launch_authorized",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "runtime_promotion_authorized",
        "remote_mutations",
        "r2_mutations",
    ] {
        receipt[key] = json!(false);
    }
    let mut out = tempfile::NamedTempFile::new_in(parent)?;
    out.as_file()
        .set_permissions(fs::Permissions::from_mode(0o400))?;
    serde_json::to_writer_pretty(out.as_file_mut(), &receipt)?;
    out.write_all(b"\n")?;
    out.as_file().sync_all()?;
    out.persist_noclobber(&p.output)
        .map_err(|e| anyhow::anyhow!("private 223 admission occupied: {e}"))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e:#}");
        std::process::exit(1)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Value {
        let floor = 2_000_000_000_000u64;
        let memory = json!({"candidate_memory_max_bytes":64u64<<30,"memory_target_percent":90,
            "host_total_memory_bytes":1000u64<<30,"protected_existing_memory_growth_bytes":80u64<<30,
            "minimum_available_memory_bytes":244u64<<30,"sampled_available_memory_bytes":244u64<<30,
            "actual_available_memory_bytes":244u64<<30});
        json!({"schema":"jetstreamer-private223-assembly-capacity-v1","self_sha256":"a".repeat(64),
            "assembly_only_no_replay":true,"all_live_growth_and_century_floor_protected":true,
            "first_epoch":201,"last_epoch":300,"new_resource_samples":0,"additional_bytes":(160u64<<30)+(32<<20),
            "recorded_unix_seconds":1000,"replay_launch_authorized":false,"local_retirement_authorized":false,
            "publication_authorized":false,"r2_mutations":false,"assembly_launch_authorized":false,
            "source_completion_authenticated":false,"minimum_free_bytes":floor,
            "required_initial_free_bytes":floor+(160u64<<30)+(32<<20),"sampled_available_bytes":floor+(160u64<<30)+(32<<20),
            "actual_available_bytes":floor+(160u64<<30)+(32<<20),"memory_before":memory,"memory_after":memory})
    }
    #[test]
    fn admission_keeps_capacity_tool_identity_floor_memory_and_freshness_closed() {
        let good = fixture();
        assert_eq!(
            capacity(&good, &"a".repeat(64), 1000).unwrap(),
            (2_000_000_000_000, 244u64 << 30)
        );
        capacity(&good, &"a".repeat(64), 1900).unwrap();
        assert!(capacity(&good, &"a".repeat(64), 1901).is_err());
        assert!(capacity(&good, &"a".repeat(64), 999).is_err());
        assert!(capacity(&good, &"b".repeat(64), 1000).is_err());
        for (pointer, value) in [
            ("/assembly_launch_authorized", json!(true)),
            ("/source_completion_authenticated", json!(true)),
            ("/r2_mutations", json!(true)),
            ("/additional_bytes", json!(159u64 << 30)),
            ("/minimum_free_bytes", json!(1_999_999_999_999u64)),
            ("/actual_available_bytes", json!(0)),
            ("/memory_before/memory_target_percent", json!(95)),
            (
                "/memory_after/protected_existing_memory_growth_bytes",
                json!(81u64 << 30),
            ),
            (
                "/memory_before/actual_available_memory_bytes",
                json!((244u64 << 30) - 1),
            ),
            (
                "/memory_after/candidate_memory_max_bytes",
                json!(63u64 << 30),
            ),
        ] {
            let mut bad = good.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(capacity(&bad, &"a".repeat(64), 1000).is_err(), "{pointer}");
        }
    }
    #[test]
    fn admission_has_separate_fixed_namespace_and_no_caller_defined_gates() {
        let bound = json!({"path":"/sealed/input.json","sha256":"a".repeat(64)});
        let good = json!({"schema":"jetstreamer-private223-assembly-admission-request-v1",
            "handoff_request":bound,"handoff_receipt":bound,"capacity":bound,
            "capacity_tool_sha256":"a".repeat(64),"assembler_sha256":"b".repeat(64),
            "output":"/var/lib/jetstreamer/horizon-223-assembly-admission-test/admission.json"});
        scope(&serde_json::from_value(good.clone()).unwrap()).unwrap();
        let mut bad = good.clone();
        bad["output"] = json!("/var/lib/jetstreamer/horizon-144-admission-test/admission.json");
        assert!(scope(&serde_json::from_value(bad).unwrap()).is_err());
        let mut bad = good;
        bad["admitted"] = json!(true);
        assert!(serde_json::from_value::<Plan>(bad).is_err());
    }
}
