//! Exact private tail reread, never full-prefix or publication qualification.
use super::*;

const PREFIX: &str = "qualification-223-v1625-tail-";
const WORKER: &str = "fde3ba53cc52012b894bac29bd7889b4cfd326fff75f4f67ec4cbdbf2ac7136c";
const ACCOUNTS: &str = "3SdyhqCuei4esVf8imz8A2rPB1z83sAK3KHbtKefJDS7";
const BANK: &str = "EWtQnBfEHcQ5hASVyH6u3LXT6WLu5MwWML6VKGg4MdxB";
const REVISION: &str = "7de8a55b54d3e11058b82f9483bb405d143b455c";

pub(super) fn namespace(a: &Arguments) -> bool {
    a.private_root
        .file_name()
        .and_then(|s| s.to_str())
        .is_some_and(|s| s.starts_with(PREFIX))
}
pub(super) fn matches(a: &Arguments) -> bool {
    a.private_root.parent() == Some(Path::new("/home/ubuntu/.jetstreamer-private"))
        && a.private_root
            .file_name()
            .and_then(|s| s.to_str())
            .and_then(|s| s.strip_prefix(PREFIX))
            .is_some_and(|s| {
                !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
        && a.archive == a.private_root.join("output/epoch-223.jet")
        && a.expected_epoch == 223
        && a.expected_output_start_slot == 96_767_523
        && a.expected_bootstrap_slot == 96_767_522
        && a.expected_terminal_slot == 96_767_999
        && a.expected_runtime_profile == "solana-v1.6.25"
        && a.expected_worker_sha256 == WORKER
        && a.expected_conflict.is_none()
}
pub(super) fn validate_bootstrap(
    a: &Arguments,
    accounts: &str,
    bank: &str,
    revision: &str,
) -> Result<(), String> {
    if namespace(a) && (!matches(a) || accounts != ACCOUNTS || bank != BANK || revision != REVISION)
    {
        return Err(
            "epoch 223 tail must bind its exact canonical bootstrap hashes and runtime revision"
                .into(),
        );
    }
    Ok(())
}
pub(super) fn annotate(a: &Arguments, receipt: &mut serde_json::Value) {
    if matches(a) {
        receipt["qualification_scope"] = json!({
            "tail_comparison_only":true,
            "complete_epoch_span_covered":false,
            "canonical_prefix_qualified":false,
            "full_cold_epoch_peak_qualified":false,
            "terminal_canonical_root_independently_known":false,
            "runtime_promotion_authorized":false,
            "canonical_sidecar_authorized":false,
            "publication_authorized":false,
            "remote_mutations":false,
            "r2_mutations":false
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args() -> Arguments {
        let root =
            PathBuf::from("/home/ubuntu/.jetstreamer-private/qualification-223-v1625-tail-test");
        Arguments {
            archive: root.join("output/epoch-223.jet"),
            private_root: root,
            receipt: None,
            expected_epoch: 223,
            expected_output_start_slot: 96_767_523,
            expected_bootstrap_slot: 96_767_522,
            expected_terminal_slot: 96_767_999,
            expected_runtime_profile: "solana-v1.6.25".into(),
            expected_worker_sha256: WORKER.into(),
            expected_conflict: None,
        }
    }
    #[test]
    fn only_exact_tail_range_worker_and_private_namespace_are_accepted() {
        let good = args();
        assert!(matches(&good));
        assert_eq!(
            good.expected_terminal_slot - good.expected_output_start_slot + 1,
            477
        );
        validate_archive_name(&good, &good.archive).unwrap();
        for change in 0..8 {
            let mut a = args();
            match change {
                0 => a.expected_epoch = 224,
                1 => a.expected_output_start_slot = 96_336_000,
                2 => a.expected_bootstrap_slot = 96_335_538,
                3 => a.expected_terminal_slot = 96_768_000,
                4 => a.expected_runtime_profile = "solana-v1.6.20".into(),
                5 => a.expected_worker_sha256 = "a".repeat(64),
                6 => {
                    a.private_root = "/home/ubuntu/horizon".into();
                    a.archive = a.private_root.join("epoch-223.jet");
                }
                _ => {
                    a.private_root =
                        "/home/ubuntu/.jetstreamer-private/qualification-223-v1625-tail-".into();
                    a.archive = a.private_root.join("output/epoch-223.jet");
                }
            }
            assert!(!matches(&a), "{change}");
            assert!(validate_archive_name(&a, &a.archive).is_err(), "{change}");
        }
    }
    #[test]
    fn reserved_namespace_cannot_escape_into_generic_through_slot_validation() {
        let mut a = args();
        a.archive = a.private_root.join("epoch-223-through-96767999.jet");
        assert!(validate_archive_name(&a, &a.archive).is_err());
        let mut a = args();
        a.expected_worker_sha256 = "0".repeat(64);
        a.archive = a.private_root.join("epoch-223-through-96767999.jet");
        assert!(validate_archive_name(&a, &a.archive).is_err());
    }
    #[test]
    fn canonical_bootstrap_hashes_and_revision_are_independently_bound() {
        let a = args();
        validate_bootstrap(&a, ACCOUNTS, BANK, REVISION).unwrap();
        for (accounts, bank, revision) in [
            ("wrong", BANK, REVISION),
            (ACCOUNTS, "wrong", REVISION),
            (ACCOUNTS, BANK, "wrong"),
        ] {
            assert!(validate_bootstrap(&a, accounts, bank, revision).is_err());
        }
    }
    #[test]
    fn successful_tail_receipt_explicitly_denies_full_epoch_and_publication_authority() {
        let mut r = json!({"validation":"pass"});
        annotate(&args(), &mut r);
        let scope = &r["qualification_scope"];
        assert_eq!(scope["tail_comparison_only"], true);
        for (key, value) in scope.as_object().unwrap() {
            if key != "tail_comparison_only" {
                assert_eq!(value, &json!(false), "{key}");
            }
        }
        let mut a = args();
        a.private_root = "/private".into();
        let mut generic = json!({"validation":"pass"});
        annotate(&a, &mut generic);
        assert!(generic.get("qualification_scope").is_none());
    }
}
