use super::{Arguments, parse_successful_transaction};
use jetstreamer_node::segment_manifest::HistoricalSegmentManifest;
use std::path::Path;

const ROOT: &str = "/home/ubuntu/.jetstreamer-private/epoch230-vote-boundary-demotion-tmpfs-v1/run";
const ARCHIVE: &str = "epoch-230-vote-boundary-demotion-diagnostic.jet";
const WORKER: &str = "d8b7865f19ebca62b8695fc9887f6215f7f680ea8a47a937caa2d49123a5af84";
const RUNTIME: &str = "solana-v1.6.20-epoch230-vote-boundary-demotion-candidate";
const TRANSACTION: &str = "99435889,1618,Z3HdXzUAZ57yeWrMib3rNiorVvMyJpKvWfTeTy2VjSt1jjECLPnn2bXjoPVxfjP7k25Wek2GUnFPpSsNBYXxqsS,5000";

pub(super) fn namespace(archive: &Path) -> bool {
    archive.file_name().and_then(|name| name.to_str()) == Some(ARCHIVE)
}

pub(super) fn matches(arguments: &Arguments) -> bool {
    arguments.private_root == Path::new(ROOT)
        && arguments.archive == Path::new(ROOT).join("output").join(ARCHIVE)
        && arguments.expected_epoch == 230
        && arguments.expected_output_start_slot == 99_430_285
        && arguments.expected_bootstrap_slot == 99_430_284
        && arguments.expected_terminal_slot == 99_437_433
        && arguments.expected_runtime_profile == RUNTIME
        && arguments.expected_worker_sha256 == WORKER
        && parse_successful_transaction(TRANSACTION).is_ok_and(|expected| {
            arguments.expected_successful_transaction.as_ref() == Some(&expected)
        })
}

pub(super) fn validate_roots(
    arguments: &Arguments,
    manifest: &HistoricalSegmentManifest,
) -> Result<(), String> {
    if matches(arguments)
        && (manifest.bootstrap.accounts_hash != "BNZTcU9y17US1ucG9dMqKdL2PgUpQou2PPDArWKrBoWu"
            || manifest.bootstrap.bank_hash != "8dU4h2XDLuq3LK3MPmZVJWFs6ickRpodKH41rR9Js837"
            || manifest.terminal.accounts_hash != "eAarFVYbpioWaBvd5S9RMHo1AyLbixgaTsBWLxYUaDr"
            || manifest.runtime.runtime_revision != "77bdb45d4af61fc687161ec06cc0178ff79726d5")
    {
        return Err(
            "epoch 230 vote-boundary archive does not match its pinned roots and runtime".into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_alias_requires_the_exact_vote_and_roots_scope() {
        let mut arguments = Arguments {
            archive: Path::new(ROOT).join("output").join(ARCHIVE),
            private_root: ROOT.into(),
            receipt: None,
            expected_epoch: 230,
            expected_output_start_slot: 99_430_285,
            expected_bootstrap_slot: 99_430_284,
            expected_terminal_slot: 99_437_433,
            expected_runtime_profile: RUNTIME.into(),
            expected_worker_sha256: WORKER.into(),
            expected_conflict: None,
            expected_successful_transaction: Some(
                parse_successful_transaction(TRANSACTION).unwrap(),
            ),
        };
        assert!(super::super::validate_archive_name(&arguments, &arguments.archive).is_ok());
        arguments
            .expected_successful_transaction
            .as_mut()
            .unwrap()
            .fee += 1;
        assert!(super::super::validate_archive_name(&arguments, &arguments.archive).is_err());
        arguments.expected_successful_transaction =
            Some(parse_successful_transaction(TRANSACTION).unwrap());
        arguments.expected_terminal_slot -= 1;
        assert!(super::super::validate_archive_name(&arguments, &arguments.archive).is_err());
    }
}
