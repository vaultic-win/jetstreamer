//! Closed full 210 memory policy while the original native 223 owner is live.
//! A 90 percent target never overrides native 223's internal available floor.
use super::*;

const NATIVE223_IID: &str = "e70aaf097e7c4583b216aba454145910";
const NATIVE223_FLOOR: u64 = 480 << 30;
const NEW_GUARD_MAX: u64 = 1 << 30;

fn original_native223(f: &Value) -> Result<()> {
    let active = f["active"].as_array().context("210 full active census")?;
    let rows = active
        .iter()
        .map(singleton227_admission::active_owner)
        .collect::<Result<Vec<_>>>()?;
    let native = rows
        .iter()
        .filter(|owner| owner["Id"] == prefix223_native20::UNIT)
        .collect::<Vec<_>>();
    ensure!(
        native.len() == 1,
        "210 memory policy needs the unchanged live native 223 owner"
    );
    let owner = *native[0];
    let claims = active
        .iter()
        .filter(|row| {
            singleton227_admission::active_owner(row)
                .is_ok_and(|u| u["Id"] == prefix223_native20::UNIT)
        })
        .collect::<Vec<_>>();
    ensure!(
        claims.len() == 1
            && claims[0]["epoch"] == 223
            && claims[0]["phase"] == "private-known-root-prefix"
            && claims[0]["ordinary_replay_claim"] == false
            && f["unit_census"][prefix223_native20::UNIT] == *owner
            && owner["InvocationID"] == NATIVE223_IID
            && owner["LoadState"] == "loaded"
            && owner["ActiveState"] == "active"
            && owner["SubState"] == "running"
            && owner["Result"] == "success"
            && owner["ExecMainStatus"] == "0"
            && owner["NRestarts"] == "0"
            && owner["MainPID"]
                .as_str()
                .and_then(|p| p.parse::<u64>().ok())
                .is_some_and(|p| p > 1)
            && owner["ControlGroup"] == format!("/system.slice/{}", prefix223_native20::UNIT),
        "210 native 223 available-memory floor owner or raw census changed"
    );
    Ok(())
}

pub(super) fn required(
    fleet: &Value,
    total: u64,
    protected_growth: u64,
    producer_max: u64,
) -> Result<(u64, Value)> {
    original_native223(fleet)?;
    ensure!(
        total > 0 && producer_max == singleton210::MEMORY && producer_max <= total,
        "210 full memory envelope differs"
    );
    // This preserved full 210 generation's peer memory function returns only
    // remaining hard-cgroup growth. It does not already include a floor top-up.
    let host_baseline = total.div_ceil(10);
    let effective_floor = host_baseline.max(NATIVE223_FLOOR);
    let required = effective_floor
        .checked_add(protected_growth)
        .and_then(|n| n.checked_add(producer_max))
        .and_then(|n| n.checked_add(NEW_GUARD_MAX))
        .context("210 protected memory arithmetic overflow")?;
    Ok((
        required,
        json!({"schema":"jetstreamer-full210-live223-memory-policy-v1",
            "native223_unit":prefix223_native20::UNIT,"native223_invocation_id":NATIVE223_IID,
            "host_baseline_bytes":host_baseline,"native223_available_memory_floor_bytes":NATIVE223_FLOOR,
            "effective_available_memory_floor_bytes":effective_floor,
            "candidate_producer_hard_memory_bytes":producer_max,"candidate_guard_hard_memory_bytes":NEW_GUARD_MAX,
            "protected_existing_hard_memory_growth_bytes":protected_growth,
            "required_available_memory_bytes":required,"floor_counted_once":true,
            "replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false}),
    ))
}

/// A delivery stage is charged once and has no new replay guard.
/// The original native223 identity gate is unchanged from the full210 policy.
pub(super) fn delivery_required(
    fleet: &Value,
    total: u64,
    protected_growth: u64,
    stage_max: u64,
) -> Result<(u64, Value)> {
    original_native223(fleet)?;
    ensure!(
        total > 0
            && stage_max <= total
            && matches!(stage_max,n if n==16<<30 || n==32<<30 || n==64<<30),
        "209 delivery stage hard memory envelope differs"
    );
    let baseline = total.div_ceil(10);
    let floor = baseline.max(NATIVE223_FLOOR);
    let required = floor
        .checked_add(protected_growth)
        .and_then(|n| n.checked_add(stage_max))
        .context("209 delivery protected memory arithmetic overflow")?;
    Ok((
        required,
        json!({"schema":"jetstreamer-full209-delivery-live223-memory-policy-v1",
        "native223_unit":prefix223_native20::UNIT,"native223_invocation_id":NATIVE223_IID,
        "host_baseline_bytes":baseline,"native223_available_memory_floor_bytes":NATIVE223_FLOOR,
        "effective_available_memory_floor_bytes":floor,"candidate_stage_hard_memory_bytes":stage_max,
        "candidate_guard_hard_memory_bytes":0,"protected_existing_hard_memory_growth_bytes":protected_growth,
        "required_available_memory_bytes":required,"floor_counted_once":true,
        "replay_launch_authorized":false,"publication_authorized":false,"r2_mutations":false}),
    ))
}

pub(super) fn validate_capacity(capacity: &Value) -> Result<()> {
    for stage in ["memory_before", "memory_after"] {
        let row = &capacity[stage];
        let total = row["host_total_memory_bytes"]
            .as_u64()
            .filter(|n| *n >= singleton210::MEMORY)
            .context("210 captured host memory absent")?;
        let growth = row["protected_existing_memory_growth_bytes"]
            .as_u64()
            .context("210 captured protected memory growth absent")?;
        let baseline = total.div_ceil(10);
        let floor = baseline.max(NATIVE223_FLOOR);
        let required = floor
            .checked_add(growth)
            .and_then(|n| n.checked_add(singleton210::MEMORY))
            .and_then(|n| n.checked_add(NEW_GUARD_MAX))
            .context("210 captured memory arithmetic overflow")?;
        let policy = &row["full210_memory_policy"];
        ensure!(
            policy["schema"] == "jetstreamer-full210-live223-memory-policy-v1"
                && policy["native223_unit"] == prefix223_native20::UNIT
                && policy["native223_invocation_id"] == NATIVE223_IID
                && policy["host_baseline_bytes"] == baseline
                && policy["native223_available_memory_floor_bytes"] == NATIVE223_FLOOR
                && policy["effective_available_memory_floor_bytes"] == floor
                && policy["candidate_producer_hard_memory_bytes"] == singleton210::MEMORY
                && policy["candidate_guard_hard_memory_bytes"] == NEW_GUARD_MAX
                && policy["protected_existing_hard_memory_growth_bytes"] == growth
                && policy["required_available_memory_bytes"] == required
                && policy["floor_counted_once"] == true
                && policy["replay_launch_authorized"] == false
                && policy["publication_authorized"] == false
                && policy["r2_mutations"] == false
                && row["candidate_memory_max_bytes"] == singleton210::MEMORY
                && row["minimum_available_memory_bytes"] == required
                && row["sampled_available_memory_bytes"]
                    .as_u64()
                    .is_some_and(|n| n >= required)
                && row["actual_available_memory_bytes"]
                    .as_u64()
                    .is_some_and(|n| n >= required),
            "210 capture needs both corrected guard and native 223 memory proofs: {stage}"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fleet() -> Value {
        let native = json!({"Id":prefix223_native20::UNIT,"InvocationID":NATIVE223_IID,
            "LoadState":"loaded","ActiveState":"active","SubState":"running","Result":"success",
            "ExecMainStatus":"0","NRestarts":"0","MainPID":"123",
            "ControlGroup":format!("/system.slice/{}",prefix223_native20::UNIT)});
        json!({"active":[
            {"epoch":225,"producer":{"Id":"horizon-qualify-225-natural-root-resource-shrink-budget-2f856bd-v1.service"}},
            {"epoch":209,"producer":{"Id":singleton209::UNIT}},
            {"epoch":223,"phase":"private-known-root-prefix","ordinary_replay_claim":false,"producer":native}],
            "unit_census":{(prefix223_native20::UNIT):native},
            "diagnostics":[{"epoch":204,"live":false},{"epoch":205,"live":false},{"epoch":227,"live":false,"failed_needs_repair":true}]})
    }

    #[test]
    fn delivery_charges_exact_stage_once_without_a_new_replay_guard() {
        for stage in [16u64 << 30, 32u64 << 30, 64u64 << 30] {
            let (n, p) = delivery_required(&fleet(), 1_024_000_000_000, 123, stage).unwrap();
            assert_eq!(n, (480u64 << 30) + 123 + stage);
            assert_eq!(p["candidate_guard_hard_memory_bytes"], 0);
        }
        assert!(delivery_required(&fleet(), 1_024_000_000_000, 0, 225_000_000_000).is_err());
        assert!(delivery_required(&fleet(), 1_024_000_000_000, u64::MAX, 32 << 30).is_err());
        let mut missing = fleet();
        missing["active"].as_array_mut().unwrap().pop();
        assert!(delivery_required(&missing, 1_024_000_000_000, 0, 32 << 30).is_err());
    }
    #[test]
    fn native223_floor_guard_and_every_existing_growth_byte_are_additive() {
        let f = fleet();
        let before = f.clone();
        let (n, evidence) = required(&f, 1_024_000_000_000, 123, singleton210::MEMORY).unwrap();
        assert_eq!(n, (480u64 << 30) + 225_000_000_000 + (1 << 30) + 123);
        assert_eq!(n, 741_469_817_467);
        assert_eq!(evidence["candidate_guard_hard_memory_bytes"], 1u64 << 30);
        assert_eq!(evidence["protected_existing_hard_memory_growth_bytes"], 123);
        assert_eq!(
            evidence["effective_available_memory_floor_bytes"],
            480u64 << 30
        );
        assert_eq!(
            f, before,
            "raw owners and terminal/failure history are preserved"
        );
        assert_eq!(
            required(&f, 1_024_000_000_000, 124, singleton210::MEMORY)
                .unwrap()
                .0,
            n + 1
        );
    }

    #[test]
    fn larger_host_baseline_wins_without_double_counting_the_native_floor() {
        let (n, evidence) =
            required(&fleet(), 10_000_000_000_001, 77, singleton210::MEMORY).unwrap();
        let baseline = 1_000_000_000_001u64;
        assert_eq!(evidence["host_baseline_bytes"], baseline);
        assert_eq!(evidence["effective_available_memory_floor_bytes"], baseline);
        assert_eq!(n, baseline + 225_000_000_000 + (1 << 30) + 77);
    }

    #[test]
    fn omitted_or_terminal_native_owner_never_silently_releases_its_floor() {
        let mut missing = fleet();
        missing["active"].as_array_mut().unwrap().pop();
        assert!(required(&missing, 1_024_000_000_000, 0, singleton210::MEMORY).is_err());
        let mut terminal = fleet();
        terminal["active"][2]["producer"]["ActiveState"] = json!("inactive");
        terminal["unit_census"][prefix223_native20::UNIT] =
            terminal["active"][2]["producer"].clone();
        assert!(required(&terminal, 1_024_000_000_000, 0, singleton210::MEMORY).is_err());
        let mut duplicate = fleet();
        let row = duplicate["active"][2].clone();
        duplicate["active"].as_array_mut().unwrap().push(row);
        assert!(required(&duplicate, 1_024_000_000_000, 0, singleton210::MEMORY).is_err());
    }

    #[test]
    fn changed_identity_role_or_raw_census_refuses_policy_evaluation() {
        for (pointer, value) in [
            ("/active/2/producer/InvocationID", json!("f".repeat(32))),
            ("/active/2/producer/MainPID", json!("0")),
            ("/active/2/producer/NRestarts", json!("1")),
            ("/active/2/producer/ControlGroup", json!("/another")),
            ("/active/2/epoch", json!(224)),
            ("/active/2/phase", json!("replay")),
            ("/active/2/ordinary_replay_claim", json!(true)),
            ("/unit_census", json!({})),
        ] {
            let mut bad = fleet();
            *bad.pointer_mut(pointer).unwrap() = value;
            assert!(
                required(&bad, 1_024_000_000_000, 0, singleton210::MEMORY).is_err(),
                "{pointer}"
            );
        }
        let mut replacement = fleet();
        replacement["active"][2]["producer"]["InvocationID"] = json!("f".repeat(32));
        replacement["unit_census"][prefix223_native20::UNIT] =
            replacement["active"][2]["producer"].clone();
        assert!(required(&replacement, 1_024_000_000_000, 0, singleton210::MEMORY).is_err());
    }

    #[test]
    fn envelope_substitution_and_arithmetic_overflow_fail_closed() {
        let f = fleet();
        for (total, growth, candidate) in [
            (0, 0, singleton210::MEMORY),
            (1, 0, singleton210::MEMORY),
            (1_024_000_000_000, 0, 96_000_000_000),
            (1_024_000_000_000, u64::MAX, singleton210::MEMORY),
        ] {
            assert!(required(&f, total, growth, candidate).is_err());
        }
    }

    #[test]
    fn capture_cannot_borrow_an_old_admission_or_an_underreserved_memory_proof() {
        let total = 1_024_000_000_000;
        let growth = 123;
        let (n, policy) = required(&fleet(), total, growth, singleton210::MEMORY).unwrap();
        let row = json!({"host_total_memory_bytes":total,"protected_existing_memory_growth_bytes":growth,
            "candidate_memory_max_bytes":singleton210::MEMORY,"minimum_available_memory_bytes":n,
            "sampled_available_memory_bytes":n,"actual_available_memory_bytes":n,"full210_memory_policy":policy});
        let capacity = json!({"memory_before":row,"memory_after":row});
        validate_capacity(&capacity).unwrap();
        for stage in ["memory_before", "memory_after"] {
            for (key, value) in [
                ("full210_memory_policy", Value::Null),
                ("minimum_available_memory_bytes", json!(n - 1)),
                ("sampled_available_memory_bytes", json!(n - 1)),
                ("actual_available_memory_bytes", json!(n - 1)),
            ] {
                let mut bad = capacity.clone();
                bad[stage][key] = value;
                assert!(validate_capacity(&bad).is_err(), "{stage}:{key}");
            }
            for (key, value) in [
                ("candidate_guard_hard_memory_bytes", json!(0)),
                ("native223_available_memory_floor_bytes", json!(0)),
                ("effective_available_memory_floor_bytes", json!(total / 10)),
                (
                    "protected_existing_hard_memory_growth_bytes",
                    json!(growth - 1),
                ),
                ("required_available_memory_bytes", json!(n - (1 << 30))),
                ("native223_invocation_id", json!("f".repeat(32))),
            ] {
                let mut bad = capacity.clone();
                bad[stage]["full210_memory_policy"][key] = value;
                assert!(validate_capacity(&bad).is_err(), "{stage}:{key}");
            }
        }
    }
}
