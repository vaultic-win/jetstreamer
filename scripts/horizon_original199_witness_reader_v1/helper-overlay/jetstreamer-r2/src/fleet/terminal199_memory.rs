//! Retain original199 hard promises independently of live replay classification.
//! The explicit selector authorizes historical interpretation only, never credit.
use super::*;
const STATE: &str = "retained-terminal-original199";
const CONTROLLER_STATE: &str = "retained-terminal-original199-controller";
const MEMORY: u64 = (192u64 << 30) + (512u64 << 20) + (512u64 << 20);
const DATA: u64 = 768u64 << 30;
const IID: &str = "2a1c51f557a64cd1ad691281cbb77c94";

fn selected(
    basis: &Value,
    observer: &Value,
    binding: &super::terminal199_context::Bound,
) -> Result<(
    super::terminal199_context::Retained,
    super::ordinary199::Proof,
)> {
    let context = super::terminal199_context::Retained::load(binding)?;
    let proof = super::ordinary199::load_for_context(
        &serde_json::to_value(context.original_enrollment())?,
        &context,
    )?
    .context("terminal199 enrollment absent")?;
    proof.validate_observer_retained(observer, &context)?;
    context.validate_current_observer(observer)?;
    for end in ["before", "after"] {
        let census = &basis[format!("original199_terminal_native_{end}")];
        context.validate_current_membership(census)?;
        proof.validate_native_retained(census, &context)?;
    }
    ensure!(
        basis["epoch199_promises"] == proof.accounting(),
        "terminal199 original promises missing or changed"
    );
    ensure!(
        basis["original199_terminal_context"] == serde_json::to_value(binding)?,
        "terminal199 explicit accounting selector differs"
    );
    Ok((context, proof))
}
fn row(binding: &super::terminal199_context::Bound, proof: &super::ordinary199::Proof) -> Value {
    json!({"state":STATE,"epoch":199,"unit":super::ordinary199::PRODUCER,
        "invocation_id":IID,"memory_max_bytes":MEMORY,"native_pool_suballocation":false,
        "cpu_quota_micros":10_000_000u64,
        "parent_memory_bytes":192u64<<30,"controller_memory_bytes":512u64<<20,
        "guard_memory_bytes":512u64<<20,"data_reservation_bytes":DATA,
        "memory_credit_bytes":0,"DATA_credit_bytes":0,"credit_bytes":0,
        "resource_release_qualified":false,"ordinary_replay_claim":false,
        "replay_launch_authorized":false,"publication_authorized":false,
        "original_enrollment":proof.binding,"terminal_context":binding})
}
fn disjoint(peers: &[Value]) -> Result<()> {
    ensure!(
        peers.iter().all(|p| p["state"] != STATE
            && p["invocation_id"] != IID
            && !super::ordinary199::FAMILY.iter().any(|u| p["unit"] == *u)),
        "terminal199 hard promises already counted in peer rows"
    );
    Ok(())
}
pub(super) fn current_native(context: &super::terminal199_context::Retained) -> Result<Value> {
    let mut census = serde_json::Map::new();
    for name in super::ordinary199::FAMILY {
        let observed = if super::ordinary199_census_settle::candidate(name) {
            super::ordinary199_census_settle::observe(name)?
        } else {
            super::unit(name)?
        };
        census.insert(name.into(), observed);
    }
    let census = Value::Object(census);
    context.validate_current_membership(&census)?;
    let proof = super::ordinary199::load_for_context(
        &serde_json::to_value(context.original_enrollment())?,
        context,
    )?
    .context("terminal199 enrollment absent")?;
    proof.validate_native_retained(&census, context)?;
    Ok(census)
}
pub(super) fn discovery(census: &Value) -> Value {
    json!({"state":CONTROLLER_STATE,"unit":super::ordinary199::CONTROLLER,
        "invocation_id":"dbf49bb1b72c42c584f2d3ac94259cb8","memory_max_bytes":0,
        "native_pool_suballocation":false,"original193GiB_row_owns_all_hard_promises":true,
        "native":census[super::ordinary199::CONTROLLER],"resource_release_qualified":false})
}
pub(super) fn validate_accounting(basis: &Value) -> Result<()> {
    let peers = basis["active_peer_allocations"]
        .as_array()
        .context("terminal199 peer ledger")?;
    let selected = basis
        .get("original199_terminal_context")
        .filter(|v| !v.is_null());
    let rows = peers
        .iter()
        .filter(|p| p["state"] == STATE)
        .collect::<Vec<_>>();
    if selected.is_none() {
        ensure!(
            rows.is_empty() && peers.iter().all(|p| p["state"] != CONTROLLER_STATE),
            "terminal199 row lacks explicit accounting context"
        );
        return Ok(());
    }
    ensure!(
        rows.len() == 1,
        "terminal199 full193GiB row absent or duplicated"
    );
    validate_peer(basis, rows[0])
}
fn retained_data(basis: &Value) -> Result<()> {
    let rows = basis["projected_obligations"]
        .as_array()
        .context("terminal199 DATA ledger")?;
    let matching = rows
        .iter()
        .filter(|r| r["producer_invocation_id"] == IID)
        .collect::<Vec<_>>();
    ensure!(
        matching.len() == 1
            && matching[0]["epoch"] == 199
            && matching[0]["claim_key"] == format!("epoch199/current-enrolled-growth/{IID}")
            && matching[0]["outstanding_bytes"] == DATA,
        "terminal199 full DATA obligation missing, changed or duplicated"
    );
    Ok(())
}
/// Call after the current native and DATA passes, before persisting accounting.
/// The full193GiB is appended once as an independent, unpooled raw peer promise.
/// Parent/controller/guard RSS is not a replacement for that hard promise.
pub(super) fn append(
    basis: &mut Value,
    observer: &Value,
    binding: &super::terminal199_context::Bound,
) -> Result<()> {
    let (context, proof) = selected(basis, observer, binding)?;
    retained_data(basis)?;
    let peers = basis["active_peer_allocations"]
        .as_array_mut()
        .context("terminal199 peer ledger")?;
    disjoint(peers)?;
    peers.push(row(binding, &proof));
    context.revalidate_inputs()?;
    Ok(())
}
/// Reauthenticate the JSON boundary wherever the raw peer total is consumed.
/// This makes a forged row or a duplicate193GiB contribution fail closed.
pub(super) fn validate_peer(basis: &Value, peer: &Value) -> Result<()> {
    let binding: super::terminal199_context::Bound =
        serde_json::from_value(peer["terminal_context"].clone())?;
    let observer_binding: super::ordinary199::Bound =
        serde_json::from_value(basis["observer"].clone())?;
    let observer = super::ordinary199::read(&observer_binding)?;
    let (context, proof) = selected(basis, &observer, &binding)?;
    ensure!(
        *peer == row(&binding, &proof),
        "terminal199 complete raw memory row changed"
    );
    retained_data(basis)?;
    let peers = basis["active_peer_allocations"]
        .as_array()
        .context("terminal199 peer ledger")?;
    let exact = peers
        .iter()
        .filter(|r| r["state"] == STATE)
        .collect::<Vec<_>>();
    ensure!(
        exact.len() == 1 && exact[0] == peer,
        "terminal199 memory promise duplicated"
    );
    let others = peers
        .iter()
        .filter(|r| r["state"] != STATE)
        .cloned()
        .collect::<Vec<_>>();
    disjoint(&others)?;
    let hard = basis["current_owner_hard_limits"]
        .as_object()
        .context("terminal199 complete hard limits")?;
    ensure!(
        super::ordinary199::FAMILY
            .iter()
            .all(|u| !hard.contains_key(*u)),
        "terminal199 hard promise appears in current ordinary caps too"
    );
    context.revalidate_inputs()?;
    Ok(())
}

pub(super) fn cpu_quota(peer: &Value) -> Result<u64> {
    ensure!(
        peer["state"] == STATE
            && peer["unit"] == super::ordinary199::PRODUCER
            && peer["invocation_id"] == IID
            && peer["memory_max_bytes"] == MEMORY
            && peer["data_reservation_bytes"] == DATA
            && peer["cpu_quota_micros"] == 10_000_000u64,
        "terminal199 retained CPU promise differs"
    );
    Ok(10_000_000)
}

/// Reauthenticate retained terminal ownership before the existing checked sum.
pub(super) fn raw_peer_memory(accounting: &Value) -> Result<u64> {
    validate_accounting(accounting)?;
    super::charge136_retry0005::contract::memory::raw_peer_memory(accounting)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn legacy_peer_sum_preserves_unpooled_and_pooled_ownership() {
        let accounting = json!({"active_peer_allocations":[
            {"unit":"legacy-a.service","memory_max_bytes":8u64<<30},
            {"unit":"legacy-b.service","memory_max_bytes":4u64<<30,"native_pool_suballocation":false},
            {"unit":"pooled.service","memory_max_bytes":512u64<<20,"native_pool_suballocation":true}
        ]});
        assert_eq!(raw_peer_memory(&accounting).unwrap(), 12u64 << 30);
    }
    #[test]
    fn terminal_row_requires_an_explicit_accounting_selector() {
        let accounting = json!({"active_peer_allocations":[{"state":"retained-terminal-original199","memory_max_bytes":193u64<<30}]});
        let error = validate_accounting(&accounting).unwrap_err().to_string();
        assert!(
            error.contains("row lacks explicit accounting context"),
            "{error}"
        );
    }
    #[test]
    fn selected_accounting_rejects_missing_or_duplicate_terminal_rows() {
        for rows in [
            json!([]),
            json!([{"state":"retained-terminal-original199"},{"state":"retained-terminal-original199"}]),
        ] {
            let accounting = json!({"original199_terminal_context":{"test_only_count_gate":true},"active_peer_allocations":rows});
            let error = validate_accounting(&accounting).unwrap_err().to_string();
            assert!(error.contains("row absent or duplicated"), "{error}");
        }
    }
    #[test]
    fn actual_raw_peer_entrypoint_cannot_bypass_terminal_validation() {
        let accounting = json!({"active_peer_allocations":[{"state":"retained-terminal-original199","memory_max_bytes":193u64<<30,"native_pool_suballocation":false}]});
        assert_eq!(
            super::super::charge136_retry0005::contract::memory::raw_peer_memory(&accounting)
                .unwrap(),
            193u64 << 30
        );
        let error = raw_peer_memory(&accounting).unwrap_err().to_string();
        assert!(
            error.contains("row lacks explicit accounting context"),
            "{error}"
        );
    }
    #[test]
    fn legacy_overflow_and_malformed_pool_tags_still_fail_closed() {
        let overflow = json!({"active_peer_allocations":[{"memory_max_bytes":u64::MAX},{"memory_max_bytes":1}]});
        assert!(
            raw_peer_memory(&overflow)
                .unwrap_err()
                .to_string()
                .contains("overflow")
        );
        let malformed = json!({"active_peer_allocations":[{"memory_max_bytes":1,"native_pool_suballocation":"false"}]});
        assert!(
            raw_peer_memory(&malformed)
                .unwrap_err()
                .to_string()
                .contains("malformed peer pool ownership")
        );
    }
}
