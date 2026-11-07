//! Add the independently enrolled 199 DATA promise without consuming old standing promises.
use super::*;
use crate::fleet::ordinary199 as exact;

const DATA_BYTES: u64 = 768 << 30;

pub(super) fn append(
    s: &accounting::SpecView<'_>,
    b: &accounting::BundleView<'_>,
    rows: &mut Vec<core::Obligation>,
) -> Result<()> {
    let declarations = s
        .guards
        .iter()
        .filter(|g| matches!(g.kind, GuardKind::Epoch199Append))
        .collect::<Vec<_>>();
    if b.fleet[exact::FIELD].is_null() {
        ensure!(
            declarations.is_empty(),
            "current 199 declaration lacks fleet enrollment"
        );
        return Ok(());
    }
    ensure!(
        declarations.len() == 1,
        "current 199 DATA needs one enrolled guard declaration"
    );
    let proof = super::super::io::epoch199_append::enrollment(declarations[0])?;
    ensure!(
        b.fleet[exact::FIELD] == serde_json::to_value(&proof.binding)?
            && b.fleet["epoch199_promises"] == proof.accounting(),
        "current 199 DATA promise differs from exact enrollment"
    );
    proof.validate_observer(b.observer)?;
    proof.validate_native(&b.fleet["unit_census"])?;
    proof.revalidate_inputs()?;
    append_exact(
        rows,
        &proof.enrollment.producer.invocation_id,
        proof.enrollment.candidate_data_bytes,
    )
}

pub(super) fn append_retained(
    s: &accounting::SpecView<'_>,
    b: &accounting::BundleView<'_>,
    rows: &mut Vec<core::Obligation>,
    context: &crate::fleet::terminal199_context::Retained,
) -> Result<()> {
    let declarations = s
        .guards
        .iter()
        .filter(|g| matches!(g.kind, GuardKind::Epoch199Append))
        .collect::<Vec<_>>();
    if b.fleet[exact::FIELD].is_null() {
        ensure!(
            declarations.is_empty(),
            "current 199 declaration lacks fleet enrollment"
        );
        return Ok(());
    }
    ensure!(
        declarations.len() == 1,
        "current 199 DATA needs one enrolled guard declaration"
    );
    let proof =
        super::super::io::epoch199_append::enrollment_for_context(declarations[0], context)?;
    ensure!(
        b.fleet[exact::FIELD] == serde_json::to_value(&proof.binding)?
            && b.fleet["epoch199_promises"] == proof.accounting(),
        "current 199 DATA promise differs from exact enrollment"
    );
    proof.validate_observer_retained(b.observer, context)?;
    proof.validate_native_retained(&b.fleet["unit_census"], context)?;
    proof.revalidate_inputs()?;
    append_exact(
        rows,
        &proof.enrollment.producer.invocation_id,
        proof.enrollment.candidate_data_bytes,
    )
}

fn append_exact(rows: &mut Vec<core::Obligation>, producer: &str, bytes: u64) -> Result<()> {
    ensure!(
        producer.len() == 32
            && producer
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
        "current 199 DATA producer IID is invalid"
    );
    ensure!(
        bytes == DATA_BYTES,
        "current 199 DATA reservation changed or was undercharged"
    );
    let key = format!("epoch199/current-enrolled-growth/{producer}");
    ensure!(
        rows.iter()
            .all(|r| r.claim_key != key && r.producer_invocation_id != producer),
        "current 199 DATA claim duplicates or crosses a retained owner"
    );
    rows.push(core::Obligation {
        claim_key: key,
        epoch: 199,
        producer_invocation_id: producer.into(),
        outstanding_bytes: bytes,
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    const IID: &str = "2a1c51f557a64cd1ad691281cbb77c94";
    fn old() -> Vec<core::Obligation> {
        vec![
            core::Obligation {
                claim_key: "historical/failed4".into(),
                epoch: 136,
                producer_invocation_id: "a".repeat(32),
                outstanding_bytes: 77_309_411_328,
            },
            core::Obligation {
                claim_key: "standing/additional-retained-promises".into(),
                epoch: 0,
                producer_invocation_id: String::new(),
                outstanding_bytes: 1_000_000_000_000,
            },
        ]
    }
    #[test]
    fn adds_full_independent_reservation_preserving_every_old_row() {
        let mut rows = old();
        let before = serde_json::to_value(&rows).unwrap();
        append_exact(&mut rows, IID, DATA_BYTES).unwrap();
        assert_eq!(serde_json::to_value(&rows[..2]).unwrap(), before);
        assert_eq!(rows[2].epoch, 199);
        assert_eq!(rows[2].producer_invocation_id, IID);
        assert_eq!(rows[2].outstanding_bytes, DATA_BYTES);
    }
    #[test]
    fn standing_frontier_cannot_absorb_the_new_reservation() {
        let mut rows = old();
        let before = rows.iter().map(|r| r.outstanding_bytes).sum::<u64>();
        append_exact(&mut rows, IID, DATA_BYTES).unwrap();
        assert_eq!(
            rows.iter().map(|r| r.outstanding_bytes).sum::<u64>(),
            before + DATA_BYTES
        );
        assert_eq!(rows[1].outstanding_bytes, 1_000_000_000_000);
    }
    #[test]
    fn undercharge_expansion_and_zero_are_rejected_without_row_changes() {
        for bytes in [0, DATA_BYTES - 1, DATA_BYTES + 1] {
            let mut rows = old();
            let before = serde_json::to_value(&rows).unwrap();
            assert!(append_exact(&mut rows, IID, bytes).is_err());
            assert_eq!(serde_json::to_value(&rows).unwrap(), before);
        }
    }
    #[test]
    fn duplicate_current_owner_or_claim_key_is_rejected() {
        let mut rows = old();
        append_exact(&mut rows, IID, DATA_BYTES).unwrap();
        assert!(append_exact(&mut rows, IID, DATA_BYTES).is_err());
        let mut rows = old();
        rows[0].producer_invocation_id = IID.into();
        assert!(append_exact(&mut rows, IID, DATA_BYTES).is_err());
        let mut rows = old();
        rows[0].claim_key = format!("epoch199/current-enrolled-growth/{IID}");
        assert!(append_exact(&mut rows, IID, DATA_BYTES).is_err());
    }
    #[test]
    fn malformed_or_foreign_shape_iid_does_not_add_a_promise() {
        for iid in [
            "",
            "not-an-invocation",
            "ABCDEF0123456789ABCDEF0123456789",
            "g0123456789012345678901234567890",
        ] {
            let mut rows = old();
            assert!(append_exact(&mut rows, iid, DATA_BYTES).is_err());
            assert_eq!(rows.len(), 2);
        }
    }
    #[test]
    fn older_same_epoch_owner_stays_independent_and_unchanged() {
        let mut rows = old();
        rows[0].epoch = 199;
        let before = serde_json::to_value(&rows[0]).unwrap();
        append_exact(&mut rows, IID, DATA_BYTES).unwrap();
        assert_eq!(serde_json::to_value(&rows[0]).unwrap(), before);
        assert_eq!(rows.iter().filter(|r| r.epoch == 199).count(), 2);
    }
}
