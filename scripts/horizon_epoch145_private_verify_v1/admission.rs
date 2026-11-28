//! Actual opaque memory/DATA construction and exact completed-export lineage.
use crate::{custody as f, model::*};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{fs, path::Path};
#[path = "bridge_client.rs"]
mod bridge_client;

fn n(v: &Value, k: &str) -> Result<u64> {
    v[k].as_u64()
        .with_context(|| format!("missing integer {k}"))
}
pub fn add(v: &[u64]) -> Result<u64> {
    v.iter()
        .try_fold(0u64, |a, b| a.checked_add(*b).context("resource overflow"))
}
pub fn false_authority() -> Value {
    json!({"runtime_promotion_authorized":false,"canonical_sidecar_authorized":false,
        "publication_authorized":false,"retirement_authorized":false,"r2_mutations":false,"replay_launch_authorized":false})
}
pub fn plan_shape(p: &Plan, now: u64) -> Result<()> {
    ensure!(
        p.schema == "horizon-epoch145-private-verification-plan-v1"
            && !p.generation.is_empty()
            && p.generation.len() <= 64
            && p.generation
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
        "exact145 verification generation"
    );
    ensure!(
        p.actor_unit
            == format!(
                "horizon-verify145-{}-{}.service",
                p.stage.name(),
                p.generation
            )
            && p.guard_unit
                == format!(
                    "horizon-guard145-verify-{}-{}.service",
                    p.stage.name(),
                    p.generation
                )
            && p.timer_unit
                == format!(
                    "horizon-guard145-verify-{}-{}.timer",
                    p.stage.name(),
                    p.generation
                )
            && p.state_root
                == Path::new("/var/lib/jetstreamer").join(format!(
                    "horizon-epoch145-private-verify-{}-{}",
                    p.stage.name(),
                    p.generation
                ))
            && p.source.path == Path::new(SOURCE)
            && p.output_root == Path::new(SOURCE).parent().unwrap()
            && p.terminal.path == Path::new(WITNESS)
            && p.terminal.sha256 == WITNESS_SHA,
        "exact private scan namespaces"
    );
    ensure!(
        p.export_plan.path
            == Path::new(
                "/usr/local/lib/jetstreamer/horizon-epoch145-prefix-extractor-plan-real1328-20261106-v1/plan.json"
            )
            && p.export_plan.sha256 == EXPORT_PLAN_SHA
            && p.incoming
                == Bound {
                    path: INCOMING.into(),
                    sha256: INCOMING_SHA.into()
                }
            && p.terminal_boundary
                == Bound {
                    path: TERMINAL.into(),
                    sha256: TERMINAL_SHA.into()
                },
        "exact independently acquired boundaries and export plan"
    );
    ensure!(
        p.actor_memory_bytes == 64 * GIB
            && p.guard_memory_bytes == 256 << 20
            && p.external_pool_bytes == 6 * GIB
            && p.actor_cpu_quota_micros == 8_000_000
            && p.guard_cpu_quota_micros == 1_000_000
            && p.tasks_max == 512
            && p.minimum_free_bytes >= MIN_DATA_FLOOR,
        "private scan resource profile"
    );
    ensure!(
        p.issued_at <= now
            && now <= p.entry_deadline
            && p.entry_deadline
                .checked_sub(p.issued_at)
                .is_some_and(|n| n <= 240)
            && p.execution_deadline
                .checked_sub(p.entry_deadline)
                .is_some_and(|n| n > 0 && n <= 86400),
        "original scan clocks"
    );
    ensure!(
        p.program.path.parent().and_then(Path::parent)
            == Some(Path::new("/usr/local/lib/jetstreamer"))
            && p.program
                .path
                .file_name()
                .is_some_and(|n| n == "epoch145-private-verify")
            && p.program
                .path
                .parent()
                .and_then(Path::file_name)
                .and_then(|n| n.to_str())
                .is_some_and(|s| s.starts_with("horizon-epoch145-private-verify-tools-"))
            && p.program_seal.path
                == p.program
                    .path
                    .parent()
                    .unwrap()
                    .join("deployment-seal-receipt.json"),
        "normal verification program namespace"
    );
    ensure!(
        p.verifier.sha256
            == match p.stage {
                Stage::Full => FULL_SHA,
                Stage::Plugin => PLUGIN_SHA,
            }
            && p.verifier.path.file_name().is_some_and(|n| n
                == match p.stage {
                    Stage::Full => "verify_archive",
                    Stage::Plugin => "horizon_pipeline",
                })
            && p.verifier.path.parent().and_then(Path::parent)
                == Some(Path::new("/usr/local/lib/jetstreamer"))
            && p.verifier_seal.path
                == p.verifier
                    .path
                    .parent()
                    .unwrap()
                    .join("deployment-seal-receipt.json"),
        "exact independently qualified verifier"
    );
    Ok(())
}
fn normal_member(program: &Bound, seal: &Bound, maximum: u64) -> Result<()> {
    f::bytes(program, maximum, true)?;
    let s = f::json(seal, true)?;
    let name = program
        .path
        .file_name()
        .context("program name")?
        .to_str()
        .context("program UTF8")?;
    ensure!(
        s["schema"] == "jetstreamer-sealed-deployment-receipt-v1"
            && s["destination"] == program.path.parent().unwrap().to_string_lossy().as_ref()
            && s["members"].as_array().is_some_and(|rows| rows
                .iter()
                .filter(|r| r["name"] == name
                    && r["sha256"] == program.sha256
                    && r["mode"] == "0555")
                .count()
                == 1),
        "exact normal-seal program member"
    );
    Ok(())
}
pub fn authenticate_program(p: &Plan, supplied: &str) -> Result<()> {
    ensure!(
        supplied == p.program.sha256
            && f::hex(supplied, 64)
            && fs::read_link("/proc/self/exe")? == p.program.path,
        "separate running verifier self binding"
    );
    normal_member(&p.program, &p.program_seal, 128 << 20)?;
    normal_member(&p.verifier, &p.verifier_seal, 512 << 20)
}

/// All values come from descriptor-checked immutable metadata, before source access.
#[allow(clippy::too_many_arguments)]
pub fn export_values(
    c: &Value,
    ep: &Value,
    ea: &Value,
    first: &Value,
    closed: &Value,
    source: &Bound,
    identity: &Identity,
    completion: &Bound,
    admission: &Bound,
) -> Result<()> {
    ensure!(
        c["schema"] == "horizon-epoch145-guarded-private-prefix-completion-v1"
            && c["plan"]["sha256"] == EXPORT_PLAN_SHA
            && c["actor_iid"] == EXPORT_IID
            && c["admission"] == json!(admission)
            && c["authority"] == false_authority(),
        "genuine145 exporter completion"
    );
    let e = &c["extraction"];
    ensure!(
        e["schema"] == "jetstreamer-private-epoch145-canonical-prefix-extraction-v1"
            && e["epoch"] == 145
            && e["source_archive"] == ORIGINAL_SOURCE
            && e["source_archive_sha256"] == SOURCE_SHA
            && e["source_manifest_sha256"] == MANIFEST_SHA
            && e["source_canonical_checkpoint_slot"] == 63072070u64
            && e["source_canonical_accounts_hash"]
                == "DsoBNgzFVZ7j5bF2CpKnt7HAC7fRrMMwdWW9FUafRe1p"
            && e["worker_sha256"]
                == "2cca500106d274ebfbbc8c5bfa0e6e8343cd5e41003f9e82c93282800732d8c8"
            && e["archive"] == SOURCE
            && source.path == Path::new(SOURCE)
            && f::hex(&source.sha256, 64)
            && e["archive_sha256"] == source.sha256
            && e["archive_bytes"] == identity.bytes
            && identity.bytes > 0
            && identity.bytes <= 160 * GIB
            && e["output_slot_start"] == 62640000u64
            && e["output_slot_count"] == 432000u64
            && e["retained_verification_tail_slots"] == 71
            && e["source_must_be_retained"] == true
            && e["independent_output_reread_passed"] == true
            && e["expected_output_provenance_sha256"]
                .as_str()
                .is_some_and(|s| f::hex(s, 64))
            && e["output_semantic_sha256"]
                .as_str()
                .is_some_and(|s| f::hex(s, 64)),
        "canonical145 width/digest/provenance lineage"
    );
    for k in [
        "current_plugin_verification_passed",
        "canonical_sidecar_authorized",
        "publication_authorized",
        "retirement_authorized",
        "r2_mutations",
    ] {
        ensure!(e[k] == false, "exporter grants independent authority: {k}");
    }
    ensure!(
        ep["schema"] == "horizon-epoch145-private-prefix-extractor-plan-v1"
            && ep["program"]["sha256"] == EXPORT_PROGRAM_SHA
            && ep["actor_unit"] == EXPORT_UNIT
            && ep["source"]["path"] == ORIGINAL_SOURCE
            && ep["source"]["sha256"] == SOURCE_SHA
            && ep["manifest"]["sha256"] == MANIFEST_SHA,
        "exporter's real original plan"
    );
    ensure!(
        ea["schema"] == "horizon-epoch145-private-extraction-typed-admission-v1"
            && ea["plan"] == c["plan"]
            && ea["actor_iid"] == EXPORT_IID
            && ea["actor_pid"] == c["actor_pid"]
            && ea["actor_start_ticks"] == c["actor_start_ticks"]
            && first["schema"] == "horizon-epoch145-actual-pre-read-guard-v1"
            && first["plan"] == c["plan"]
            && first["admission"] == c["admission"]
            && first["token"]["actor_iid"] == EXPORT_IID
            && first["token"]["actor_pid"] == ea["actor_pid"]
            && first["token"]["actor_start_ticks"] == ea["actor_start_ticks"]
            && first["token"]["plan"] == c["plan"]
            && first["token"]["admission"] == c["admission"],
        "exporter's genuine pre-read guard/admission chain"
    );
    ensure!(
        closed["schema"] == "horizon-epoch145-production-export-original-completion-v1"
            && closed["completion"] == json!(completion)
            && closed["admission"] == json!(admission)
            && closed["unit"] == EXPORT_UNIT
            && closed["invocation_id"] == EXPORT_IID
            && closed["result"] == "success"
            && closed["exec_main_status"] == 0
            && closed["original_outer_reaped"] == true
            && closed["original_cgroup_empty"] == true
            && closed["original_descriptors_drained"] == true
            && closed["original_export_guard_and_timer_drained"] == true
            && closed["PID1"]
                .as_array()
                .is_some_and(|rows| rows.iter().any(|r| r["_PID"] == "1"
                    && r["_UID"] == "0"
                    && r["UNIT"] == EXPORT_UNIT
                    && r["INVOCATION_ID"] == EXPORT_IID
                    && r["MESSAGE_ID"] == "7ad2d189f7e94e70a38c781354912448")),
        "original export completion/drain required"
    );
    Ok(())
}
pub fn source_metadata(p: &Plan) -> Result<()> {
    ensure!(
        f::frozen_identity(&p.source.path)? == p.source_identity
            && f::frozen_identity(&p.manifest.path)? == p.manifest_identity,
        "frozen completed canonical archive/receipt changed"
    );
    f::evidence(&p.terminal)?;
    f::evidence(&p.incoming)?;
    f::evidence(&p.terminal_boundary)?;
    let c = f::json(&p.manifest, true)?;
    export_values(
        &c,
        &f::json(&p.export_plan, true)?,
        &f::json(&p.export_admission, true)?,
        &f::json(&p.export_first_guard, true)?,
        &f::json(&p.export_original_completion, true)?,
        &p.source,
        &p.source_identity,
        &p.manifest,
        &p.export_admission,
    )
}
pub fn fresh(p: &Plan, pb: &Bound, iid: &str, start: u64, original: Value) -> Result<Admission> {
    let now = f::now()?;
    plan_shape(p, now)?;
    source_metadata(p)?;
    let proof = bridge_client::call(p, pb, None)?;
    let me = proof["memory_evidence"].clone();
    let de = proof["data_evidence"].clone();
    ensure!(
        de["current"] == me["request"]["current"],
        "crossed current typed tuples"
    );
    let obs = f::evidence(&serde_json::from_value(
        me["request"]["current"]["observer"].clone(),
    )?)?;
    let raw = f::evidence(&serde_json::from_value::<Bound>(
        de["raw_accounting"].clone(),
    )?)?;
    let memory = n(&proof, "effective_total_memory_bytes")?;
    let data = n(&proof, "effective_protected_DATA_bytes")?;
    let mem = add(&[
        memory,
        p.external_pool_bytes,
        p.actor_memory_bytes,
        p.guard_memory_bytes,
        MIN_UNCOVERED_MEMORY_BYTES,
    ])?;
    let disk = add(&[data, MAX_METADATA_BYTES])?;
    let host = n(&obs["host_memory"], "total_kib")?
        .checked_mul(1024)
        .context("host overflow")?;
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
                    .context("CPU overflow")?
            && mem <= host
            && disk <= n(&obs["filesystem"], "conservative_available_bytes")?
            && p.minimum_free_bytes >= data.max(n(&raw, "inherited_live_guard_maximum_bytes")?)
            && p.minimum_available_memory_bytes >= mem,
        "complete private scan resource admission"
    );
    ensure!(
        de["projection"]["proposed_obligations"]
            .as_array()
            .is_some_and(|rows| rows
                .iter()
                .any(|r| r["claim_key"] == format!("cached145/{ORIGINAL_IID}")
                    && r["outstanding_bytes"] == 337 * GIB)),
        "retained original source obligation"
    );
    Ok(Admission {
        schema: "horizon-epoch145-private-verification-typed-admission-v1".into(),
        plan: pb.clone(),
        actor_unit: p.actor_unit.clone(),
        actor_iid: iid.into(),
        actor_pid: std::process::id(),
        actor_start_ticks: start,
        accepted_at: now,
        accepted_boottime_millis: f::boottime()?,
        memory_evidence: me,
        data_evidence: de,
        existing_memory_bytes: memory,
        protected_existing_data_bytes: data,
        required_initial_memory_bytes: mem,
        required_initial_data_bytes: disk,
        original_native: original,
    })
}
pub fn continuity(p: &Plan, pb: &Bound, a: &Admission) -> Result<()> {
    ensure!(
        a.schema == "horizon-epoch145-private-verification-typed-admission-v1"
            && a.plan == *pb
            && a.actor_unit == p.actor_unit
            && f::hex(&a.actor_iid, 32)
            && a.accepted_at >= p.issued_at
            && a.accepted_at <= p.entry_deadline
            && f::now()? <= p.execution_deadline,
        "original scan admission clock and actor"
    );
    let ab = f::binding(&p.state_root.join("admission.json"))?;
    let saved: Admission = serde_json::from_slice(&f::bytes(&ab, 8 << 20, false)?)?;
    ensure!(
        serde_json::to_value(saved)? == serde_json::to_value(a)?,
        "crossed scan admission bytes"
    );
    bridge_client::call(p, pb, Some(&ab))?;
    source_metadata(p)?;
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
                    p.guard_memory_bytes,
                    MIN_UNCOVERED_MEMORY_BYTES
                ])?
            && a.required_initial_data_bytes
                == add(&[a.protected_existing_data_bytes, MAX_METADATA_BYTES])?
            && p.minimum_free_bytes >= a.protected_existing_data_bytes
            && p.minimum_available_memory_bytes >= a.required_initial_memory_bytes,
        "scan admission arithmetic changed"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sums_never_wrap_or_subtract_source_debt() {
        assert!(add(&[u64::MAX, 1]).is_err());
        assert_eq!(
            add(&[337 * GIB, 128 << 20]).unwrap(),
            337 * GIB + (128 << 20)
        );
    }
    #[test]
    fn private_scan_grants_no_other_authority() {
        assert!(
            false_authority()
                .as_object()
                .unwrap()
                .values()
                .all(|v| v == false)
        );
    }
}
