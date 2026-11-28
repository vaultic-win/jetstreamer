//! Input-side acknowledgement after every callback for one decoded block.
//! This is not an executor drain, checkpoint, or full-range completion proof.

/// A block whose complete source callback batch returned successfully.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompletedSourceBlock {
    /// Decoded block slot.
    pub slot: u64,
    /// Decoded parent edge.
    pub parent_slot: u64,
    /// Last decoded entry hash, not a claim about executed native state.
    pub blockhash: [u8; 32],
    /// Number of entries delivered by this source batch.
    pub entries: u64,
    /// Number of transactions counted in those entries.
    pub transactions: u64,
}

/// The sequential caller's decision after a complete source block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceBlockAction {
    /// Continue accepting source input.
    Continue,
    /// End source input with an explicit quiesced outcome, never range success.
    Quiesce,
}

/// Commit retry progress and acknowledge only a successful whole block batch.
/// A metadata notification alone must not advance the caller's retry watermark.
/// The source loop must propagate Quiesce without its ordinary retry path.
pub(crate) fn acknowledge<E>(
    processed: Result<(), E>,
    block: CompletedSourceBlock,
    callback: impl FnOnce(CompletedSourceBlock) -> SourceBlockAction,
) -> Result<SourceBlockAction, E> {
    processed?;
    Ok(callback(block))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        cell::RefCell,
        sync::atomic::{AtomicBool, Ordering},
    };

    fn block() -> CompletedSourceBlock {
        CompletedSourceBlock {
            slot: 42,
            parent_slot: 40,
            blockhash: [7; 32],
            entries: 2,
            transactions: 3,
        }
    }

    #[test]
    fn acknowledgement_follows_entire_callback_batch() {
        let events = RefCell::new(Vec::new());
        let process = || -> Result<(), &'static str> {
            events
                .borrow_mut()
                .extend(["parent", "transaction", "entry", "metadata"]);
            // A metadata notification alone is deliberately not the boundary.
            events.borrow_mut().push("batch-return");
            Ok(())
        };
        assert_eq!(
            acknowledge(process(), block(), |seen| {
                assert_eq!(seen, block());
                assert_eq!(
                    *events.borrow(),
                    ["parent", "transaction", "entry", "metadata", "batch-return"]
                );
                events.borrow_mut().push("ack");
                SourceBlockAction::Quiesce
            }),
            Ok(SourceBlockAction::Quiesce)
        );
        assert_eq!(events.borrow().last(), Some(&"ack"));
    }

    #[test]
    fn failure_after_metadata_cannot_acknowledge_or_select_a_checkpoint() {
        let mut metadata_delivered = false;
        let mut process = || -> Result<(), &'static str> {
            metadata_delivered = true;
            Err("remaining block decoding failed")
        };
        assert_eq!(
            acknowledge(process(), block(), |_| panic!("acknowledged failed batch")),
            Err("remaining block decoding failed")
        );
        assert!(metadata_delivered);
    }

    #[test]
    fn failed_batch_keeps_retry_parent_until_successful_redelivery() {
        let previous = (40, [3; 32]);
        let mut retry_parent = previous;
        let mut acknowledged = Vec::new();
        // The metadata callback has run, but the decoder then rejects a node.
        let failed_batch = Err("node after metadata failed");
        let result = acknowledge(failed_batch, block(), |completed| {
            retry_parent = (completed.slot, completed.blockhash);
            acknowledged.push(completed);
            SourceBlockAction::Quiesce
        });
        assert_eq!(result, Err("node after metadata failed"));
        assert_eq!(retry_parent, previous);
        assert!(acknowledged.is_empty());
        assert!(
            block().slot > retry_parent.0,
            "failed block must be retried"
        );

        // Redeliver the entire block; commit before exposing a quiesced boundary.
        let result = acknowledge(Ok::<_, &str>(()), block(), |completed| {
            retry_parent = (completed.slot, completed.blockhash);
            acknowledged.push(completed);
            SourceBlockAction::Quiesce
        });
        assert_eq!(result, Ok(SourceBlockAction::Quiesce));
        assert_eq!(retry_parent, (42, [7; 32]));
        assert_eq!(acknowledged, [block()]);
    }

    #[test]
    fn request_during_a_block_is_observed_only_after_its_batch_returns() {
        let request = AtomicBool::new(false);
        let completed = AtomicBool::new(false);
        let process = || -> Result<(), &'static str> {
            request.store(true, Ordering::Release);
            completed.store(true, Ordering::Release);
            Ok(())
        };
        assert_eq!(
            acknowledge(process(), block(), |_| {
                assert!(completed.load(Ordering::Acquire));
                if request.load(Ordering::Acquire) {
                    SourceBlockAction::Quiesce
                } else {
                    SourceBlockAction::Continue
                }
            }),
            Ok(SourceBlockAction::Quiesce)
        );
    }

    #[test]
    fn ordinary_completion_can_continue_with_exact_boundary_identity() {
        let mut calls = 0;
        let action = acknowledge(Ok::<_, ()>(()), block(), |seen| {
            calls += 1;
            assert_eq!(seen, block());
            SourceBlockAction::Continue
        })
        .unwrap();
        assert_eq!(action, SourceBlockAction::Continue);
        assert_eq!(calls, 1);
    }
}
