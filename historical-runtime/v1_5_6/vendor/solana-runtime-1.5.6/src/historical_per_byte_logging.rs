//! Backport of the feature added by Solana 1.5 commit ccd2c6cc13f8.
use solana_sdk::process_instruction::InvokeContext;

solana_sdk::declare_id!("59dM4SV6dPEKXPfkrkhFkRdn4K6xwKxdNAPMyXG7J1wT");

pub fn is_active(invoke_context: &dyn InvokeContext) -> bool {
    cfg!(feature = "historical-per-byte-logging") && invoke_context.is_feature_active(&id())
}
