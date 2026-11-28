//! This consumer invokes the already-qualified opaque selectors. Serialized
//! selected totals and approval booleans cannot construct a memory/DATA view.
use crate::{custody as f, model::*};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{fs, path::Path};

#[path = "bridge_client.rs"]
mod bridge_client;
fn n(v: &Value, key: &str) -> Result<u64> {
    v[key]
        .as_u64()
        .with_context(|| format!("missing integer {key}"))
}
pub fn add(values: &[u64]) -> Result<u64> {
    values.iter().try_fold(0u64, |a, b| {
        a.checked_add(*b).context("resource sum overflow")
    })
}

pub fn plan_shape(p: &Plan, now: u64) -> Result<()> {
    ensure!(
        p.schema == "horizon-epoch145-private-prefix-extractor-plan-v1"
            && !p.generation.is_empty()
            && p.generation.len() <= 64
            && p.generation
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-'),
        "145 plan scope/generation"
    );
    ensure!(
        p.source.path == Path::new(SOURCE)
            && p.source.sha256 == SOURCE_SHA
            && p.manifest.path == Path::new(MANIFEST)
            && p.manifest.sha256 == MANIFEST_SHA
            && p.terminal.path == Path::new(WITNESS)
            && p.terminal.sha256 == WITNESS_SHA,
        "exact original source/witness"
    );
    ensure!(
        p.actor_unit == format!("horizon-extract145-prefix-{}.service", p.generation)
            && p.guard_unit == format!("horizon-guard145-prefix-{}.service", p.generation)
            && p.timer_unit == format!("horizon-guard145-prefix-{}.timer", p.generation)
            && p.output_root.parent() == Some(Path::new("/home/sol/.jetstreamer-private"))
            && p.output_root
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("epoch145-prefix-extract-")
                    && n.len() > 24
                    && n.len() < 128
                    && n.bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'))
            && p.state_root
                == Path::new("/var/lib/jetstreamer")
                    .join(format!("horizon-epoch145-prefix-extract-{}", p.generation)),
        "exact actor/private namespaces"
    );
    ensure!(
        (1..=160 * GIB).contains(&p.output_maximum_bytes)
            && (64 * GIB..=96 * GIB).contains(&p.actor_memory_bytes)
            && p.guard_memory_bytes == 256 << 20
            && p.external_pool_bytes == 6 * GIB
            && p.actor_cpu_quota_micros == 8_000_000
            && p.guard_cpu_quota_micros == 1_000_000
            && p.tasks_max == 512,
        "explicit bounded source/export resource profile"
    );
    ensure!(
        p.issued_at <= now
            && now <= p.entry_deadline
            && p.entry_deadline
                .checked_sub(p.issued_at)
                .is_some_and(|d| d <= 240)
            && p.execution_deadline
                .checked_sub(p.entry_deadline)
                .is_some_and(|d| d > 0 && d <= 43_200),
        "original admission clocks"
    );
    ensure!(
        p.program.path.parent().and_then(Path::parent)
            == Some(Path::new("/usr/local/lib/jetstreamer"))
            && p.program
                .path
                .file_name()
                .is_some_and(|n| n == "epoch145-prefix-extract")
            && p.program
                .path
                .parent()
                .and_then(Path::file_name)
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("horizon-epoch145-prefix-extractor-tools-"))
            && p.program_seal.path
                == p.program
                    .path
                    .parent()
                    .unwrap()
                    .join("deployment-seal-receipt.json"),
        "sealed executable namespace"
    );
    Ok(())
}

pub fn source_metadata(p: &Plan) -> Result<()> {
    ensure!(
        f::frozen_identity(&p.source.path)? == p.source_identity
            && f::frozen_identity(&p.manifest.path)? == p.manifest_identity,
        "frozen source metadata changed"
    );
    let w = f::evidence(&p.terminal)?;
    ensure!(
        w["schema"] == "horizon-cached145-authenticated-original-terminal-and-segment-v1"
            && w["epoch"] == 145
            && w["original_IID"] == ORIGINAL_IID
            && w["native"]["Id"] == ORIGINAL_UNIT
            && w["original_PID1_success_event"]["_PID"] == "1"
            && w["original_PID1_success_event"]["_UID"] == "0"
            && w["original_PID1_success_event"]["UNIT"] == ORIGINAL_UNIT
            && w["original_PID1_success_event"]["INVOCATION_ID"] == ORIGINAL_IID
            && w["original_PID1_success_event"]["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448"
            && w["archive"]["path"] == SOURCE
            && w["archive"]["bytes"] == SOURCE_BYTES
            && w["archive"]["device"] == p.source_identity.device
            && w["archive"]["inode"] == p.source_identity.inode
            && w["archive"]["mtime_ns"].as_i64().map(i128::from)
                == Some(p.source_identity.mtime_ns)
            && w["producer_recorded_archive_sha256"] == SOURCE_SHA
            && w["producer_segment_manifest"]["path"] == MANIFEST
            && w["producer_segment_manifest"]["sha256"] == MANIFEST_SHA,
        "original terminal source lineage"
    );
    // No source body is read here; the core hashes/decodes only after guard token.
    ensure!(p.source_identity.bytes == SOURCE_BYTES, "source length");
    Ok(())
}

pub fn authenticate_program(p: &Plan, supplied: &str) -> Result<()> {
    ensure!(
        supplied == p.program.sha256 && f::hex(supplied, 64),
        "separate self SHA binding"
    );
    ensure!(
        fs::read_link("/proc/self/exe")? == p.program.path,
        "running executable path"
    );
    let _ = f::bytes(&p.program, 128 << 20, true)?;
    let seal = f::json(&p.program_seal, true)?;
    ensure!(
        seal["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && seal["destination"] == p.program.path.parent().unwrap().to_string_lossy().as_ref()
            && seal["members"].as_array().is_some_and(|rows| rows
                .iter()
                .filter(|r| r["name"] == "epoch145-prefix-extract"
                    && r["sha256"] == supplied
                    && r["mode"] == "0555")
                .count()
                == 1),
        "program normal seal"
    );
    Ok(())
}

pub fn fresh(p: &Plan, pb: &Bound, iid: &str, start: u64, original: Value) -> Result<Admission> {
    let now = f::now()?;
    plan_shape(p, now)?;
    let proof = bridge_client::call(p, pb, None)?;
    let me = proof["memory_evidence"].clone();
    let de = proof["data_evidence"].clone();
    let observer = f::evidence(&serde_json::from_value(
        me["request"]["current"]["observer"].clone(),
    )?)?;
    let raw_bound: Bound = serde_json::from_value(de["raw_accounting"].clone())?;
    let raw = f::evidence(&raw_bound)?;
    ensure!(
        de["current"] == me["request"]["current"],
        "crossed typed current tuples"
    );
    let existing_memory = n(&proof, "effective_total_memory_bytes")?;
    let existing_data = n(&proof, "effective_protected_DATA_bytes")?;
    let mem = add(&[
        existing_memory,
        p.external_pool_bytes,
        p.actor_memory_bytes,
        p.guard_memory_bytes,
    ])?;
    let disk = add(&[existing_data, p.output_maximum_bytes, MAX_METADATA_BYTES])?;
    let host = n(&observer["host_memory"], "total_kib")?
        .checked_mul(1024)
        .context("host memory overflow")?;
    let free = n(&observer["filesystem"], "conservative_available_bytes")?;
    let inherited = n(&raw, "inherited_live_guard_maximum_bytes")?;
    let cpu = add(&[
        n(&raw, "current_replay_cpu_quota_micros")?,
        p.actor_cpu_quota_micros,
        p.guard_cpu_quota_micros,
    ])?;
    let logical = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    ensure!(
        logical > 0
            && cpu
                <= u64::try_from(logical)?
                    .checked_mul(1_000_000)
                    .context("CPU overflow")?,
        "host CPU envelope"
    );
    ensure!(
        mem <= host
            && disk <= free
            && p.minimum_free_bytes >= existing_data.max(inherited)
            && p.minimum_available_memory_bytes >= mem,
        "complete resource admission does not fit or lowers guard"
    );
    ensure!(
        de["projection"]["proposed_obligations"]
            .as_array()
            .is_some_and(|rows| rows
                .iter()
                .any(|r| r["claim_key"] == format!("cached145/{ORIGINAL_IID}")
                    && r["outstanding_bytes"] == 337 * GIB)),
        "retained complete source claim missing"
    );
    Ok(Admission {
        schema: "horizon-epoch145-private-extraction-typed-admission-v1".into(),
        plan: pb.clone(),
        actor_unit: p.actor_unit.clone(),
        actor_iid: iid.into(),
        actor_pid: std::process::id(),
        actor_start_ticks: start,
        accepted_at: now,
        accepted_boottime_millis: f::boottime()?,
        memory_evidence: me,
        data_evidence: de,
        existing_memory_bytes: existing_memory,
        protected_existing_data_bytes: existing_data,
        required_initial_memory_bytes: mem,
        required_initial_data_bytes: disk,
        original_native: original,
    })
}

/// No new admission or budget from this API; reauthenticate the same opaque
/// selections at their accepted original clock and check current native custody.
pub fn continuity(p: &Plan, pb: &Bound, a: &Admission) -> Result<()> {
    ensure!(
        a.schema == "horizon-epoch145-private-extraction-typed-admission-v1"
            && a.plan == *pb
            && a.actor_unit == p.actor_unit
            && f::hex(&a.actor_iid, 32)
            && a.accepted_at >= p.issued_at
            && a.accepted_at <= p.entry_deadline
            && f::now()? <= p.execution_deadline,
        "accepted source execution identity/clock"
    );
    let ab = f::binding(&p.state_root.join("admission.json"))?;
    let original: Admission = serde_json::from_slice(&f::bytes(&ab, 8 << 20, false)?)?;
    ensure!(
        serde_json::to_value(&original)? == serde_json::to_value(a)?,
        "continuity admission bytes crossed"
    );
    bridge_client::call(p, pb, Some(&ab))?;
    ensure!(
        n(&a.memory_evidence, "effective_total_memory_promises_bytes")? == a.existing_memory_bytes
            && n(
                &a.data_evidence["projection"],
                "proposed_protected_existing_DATA_bytes"
            )? == a.protected_existing_data_bytes
            && a.required_initial_memory_bytes
                == add(&[
                    a.existing_memory_bytes,
                    p.external_pool_bytes,
                    p.actor_memory_bytes,
                    p.guard_memory_bytes
                ])?
            && a.required_initial_data_bytes
                == add(&[
                    a.protected_existing_data_bytes,
                    p.output_maximum_bytes,
                    MAX_METADATA_BYTES
                ])?
            && p.minimum_free_bytes >= a.protected_existing_data_bytes
            && p.minimum_available_memory_bytes >= a.required_initial_memory_bytes,
        "accepted arithmetic changed"
    );
    Ok(())
}

pub fn false_authority() -> Value {
    json!({"runtime_promotion_authorized":false,"canonical_sidecar_authorized":false,
    "publication_authorized":false,"retirement_authorized":false,"r2_mutations":false,"replay_launch_authorized":false})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn checked_resource_arithmetic_never_wraps_or_subtracts_retained_debt() {
        assert!(add(&[u64::MAX, 1]).is_err());
        assert_eq!(add(&[337 * GIB, 160 * GIB]).unwrap(), 497 * GIB);
    }
    #[test]
    fn no_publication_or_retirement_authority_is_created() {
        assert!(
            false_authority()
                .as_object()
                .unwrap()
                .values()
                .all(|v| *v == false)
        );
    }
}
